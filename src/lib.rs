use object::{Object, ObjectSection};
use gimli::{ UnwindSection, Register };
use thiserror::Error;
use std::collections::{ HashMap, BTreeMap, BTreeSet };

mod table;

#[derive(Error, Debug)]
pub enum FswError {
    #[error("File open failed")]
    FileOpenError(std::io::Error),
    #[error("MMap failed")]
    MmapError(std::io::Error),
    #[error("Object could not be parsed")]
    ObjectParseError(object::Error),
    #[error("No exception handling information in object")]
    NoEhInfo,
    #[error("Dwarf error: bad expression offset")]
    DwarfErrorExpressionOffset,
    #[error("Dwarf error: unknown register rule")]
    DwarfErrorUnknownRegisterRule,
    #[error("Gimli error")]
    GimliError(gimli::Error),
    #[error("CIE missing for FDE")]
    MissingCie,
    #[error("OID too large, needs to fit in 16 bits")]
    OidTooLarge,
    #[error("Can't encode table value")]
    TableValueEncodeError,
    #[error("Can't decode table value")]
    TableValueDecodeError,

}
use FswError::*;

type Result<T> = std::result::Result<T, FswError>;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum CfaRule {
    RegisterAndOffset(u16, i64),
    Expression(usize),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum RegisterRule {
    Undefined,
    SameValue,
    Offset(i64),
    ValOffset(i64),
    Register(Register),
    Expression(usize),
    ValExpression(usize),
    Architectural,
    Constant(u64),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct UnwindEntry {
    cfa: CfaRule,
    rules: Vec<(Register, RegisterRule)>,
    saved_args_size: u64,
}

#[derive(Debug)]
struct EvaluationContext {
    address_size: usize,
    dwarf_version: usize,
    dwarf64: bool,
}

#[derive(Debug)]
pub struct Fsw {
    unwind_table: BTreeMap<(usize, u64), Option<usize>>,
    unwind_entries: BTreeMap<usize, UnwindEntry>,
    unwind_entries_rev: BTreeMap<UnwindEntry, usize>,
    maps: BTreeMap<u64, EvaluationContext>, // XXX
    expressions: BTreeMap<usize, Vec<u8>>,
    expressions_rev: BTreeMap<Vec<u8>, usize>,
    parsing_errors: HashMap<ParsingError, u64>,
    next_entry_id: usize,
}

#[derive(Debug, PartialEq, Eq, Hash)]
enum ParsingError {
    NoError,
    BadExpressionOffset,
    UnknownRegisterRule,
    RowOverlap,
}

impl Fsw {
    pub fn new() -> Self {
        Fsw {
            unwind_table: BTreeMap::new(),
            unwind_entries: BTreeMap::new(),
            unwind_entries_rev: BTreeMap::new(),
            maps: BTreeMap::new(),
            expressions: BTreeMap::new(),
            expressions_rev: BTreeMap::new(),
            parsing_errors: HashMap::new(),
            next_entry_id: 1,
        }
    }

    // oid object id must be unique
    pub fn add_file<P: AsRef<std::path::Path>>(&mut self, path: P, oid: usize)
        -> Result<()>
    {
        if oid > 0xffff {
            return Err(OidTooLarge);
        }
        let file = std::fs::File::open(path).map_err(FileOpenError)?;

        let mmap = unsafe { memmap2::Mmap::map(&file).map_err(MmapError)? };
        let object = object::File::parse(&*mmap).map_err(ObjectParseError)?;

        let eh_frame_section = object
            .section_by_name(".eh_frame")
            .ok_or(NoEhInfo)?;

        let eh_frame_data = eh_frame_section.uncompressed_data().map_err(ObjectParseError)?;
println!("Parsing .eh_frame of size {}", eh_frame_data.len());
        let eh_frame = gimli::EhFrame::new(&eh_frame_data, gimli::NativeEndian);
        let bases = gimli::BaseAddresses::default()
            .set_eh_frame(eh_frame_section.address());
        let mut entries = eh_frame.entries(&bases);
        let mut cies = HashMap::new();
        let mut unwind_ctx = gimli::UnwindContext::new();
        while let Some(entry) = entries.next().map_err(GimliError)? {
            match entry {
                gimli::CieOrFde::Cie(cie) => {
                    cies.insert(cie.offset(), cie);
                }
                gimli::CieOrFde::Fde(partial_fde) => {
                    let fde = partial_fde.parse(
                        |_, _, o| {
                            if let Some(cie) = cies.get(&o.0) {
                                Ok(cie.clone())
                            } else {
                                Err(gimli::read::Error::Io)
                            }
                        })
                        .map_err(GimliError)?;

                    let mut table = fde.rows(&eh_frame, &bases, &mut unwind_ctx)
                        .map_err(GimliError)?;
                    let mut error = ParsingError::NoError;
                    'rows: while let Some(row) = table.next_row().map_err(GimliError)? {
                        // convert CFA
                        let cfa = match row.cfa() {
                            gimli::CfaRule::RegisterAndOffset { register, offset } => {
                                CfaRule::RegisterAndOffset(register.0, *offset)
                            }
                            gimli::CfaRule::Expression(e) => {
                                if e.offset + e.length > eh_frame_data.len() {
                                    break 'rows;
                                }
                                let expr_id = self.add_expression(Vec::from(&eh_frame_data
                                    [e.offset .. e.offset + e.length]));
                                CfaRule::Expression(expr_id)
                            }
                        };
                        // convert registers
                        let mut rules = Vec::new();
                        for (reg, rule) in row.registers() {
                            let rule = match rule {
                                gimli::RegisterRule::Undefined => RegisterRule::Undefined,
                                gimli::RegisterRule::SameValue => RegisterRule::SameValue,
                                gimli::RegisterRule::Offset(o) => RegisterRule::Offset(*o),
                                gimli::RegisterRule::ValOffset(o) => RegisterRule::ValOffset(*o),
                                gimli::RegisterRule::Register(r) => RegisterRule::Register(*r),
                                gimli::RegisterRule::Expression(e) => {
                                    if e.offset + e.length > eh_frame_data.len() {
                                        error = ParsingError::BadExpressionOffset;
                                        break 'rows;
                                    }
                                    let expr_id = self.add_expression(Vec::from(&eh_frame_data
                                        [e.offset .. e.offset + e.length]));
                                    RegisterRule::Expression(expr_id)
                                }
                                gimli::RegisterRule::ValExpression(e) => {
                                    if e.offset + e.length > eh_frame_data.len() {
                                        error = ParsingError::BadExpressionOffset;
                                        break 'rows;
                                    }
                                    let expr_id = self.add_expression(Vec::from(&eh_frame_data
                                        [e.offset .. e.offset + e.length]));
                                    RegisterRule::ValExpression(expr_id)
                                }
                                gimli::RegisterRule::Architectural => RegisterRule::Architectural,
                                gimli::RegisterRule::Constant(c) => RegisterRule::Constant(*c),
                                _ => {
                                    error = ParsingError::UnknownRegisterRule;
                                    break 'rows;
                                }
                            };
                            rules.push((reg.clone(), rule));
                        }

                        let entry = UnwindEntry {
                            cfa,
                            rules,
                            saved_args_size: row.saved_args_size(),
                        };
                        // get row index or create new
                        let entryid = if let Some(id) = self.unwind_entries_rev.get(&entry) {
                            *id
                        } else {
                            let id = self.next_entry_id;
                            self.next_entry_id += 1;
                            self.unwind_entries.insert(id, entry.clone());
                            self.unwind_entries_rev.insert(entry, id);
                            id
                        };
                        // start may override end
                        // start may not override start
                        // end overrides nothing
                        let start = row.start_address();
                        let end = row.end_address();
                        if let Some(Some(_)) = self.unwind_table.get(&(oid, start)) {
                            error = ParsingError::RowOverlap;
                            break 'rows;
                        }
                        self.unwind_table.insert((oid, start), Some(entryid));
                        if self.unwind_table.get(&(oid, end)).is_none() {
                            self.unwind_table.insert((oid, end), None);
                        }
                    }
                    if error != ParsingError::NoError {
                        *self.parsing_errors.entry(error).or_default() += 1;
                    }
                }
            }
        }
        println!("Parsing errors: {:?}", self.parsing_errors);
        println!("Unwind entries: {}", self.unwind_entries.len());
        println!("Unwind table  : {}", self.unwind_table.len());
        println!("Expressions   : {}", self.expressions.len());
        Ok(())
    }

    pub fn add_pid(&mut self, pid: u32) -> Result<()> {
        let maps = read_process_maps(pid)?;
        let mut seen = BTreeSet::new();
        for map in maps {
            if seen.contains(&map.file_path) {
                continue;
            }
            let oid = seen.len();
            seen.insert(map.file_path.clone());
            let res = self.add_file(&map.file_path, oid);
println!("Adding file: {} result {:?}", map.file_path, res);
        }

        Ok(())
    }

    fn add_expression(&mut self, expr: Vec<u8>) -> usize {
println!("expression: {:?}", expr);
        if let Some(id) = self.expressions_rev.get(&expr) {
            *id
        } else {
            let id = self.expressions.len();
            self.expressions.insert(id, expr.clone());
            self.expressions_rev.insert(expr, id);
            id
        }
    }

    pub fn build_table(&mut self) -> Result<()> {
        // sort unwind entries by occurences
        let mut entry_counts = HashMap::new();
        // count occurences
        for entry_opt in self.unwind_table.values() {
            if let Some(entry_id) = entry_opt {
                *entry_counts.entry(*entry_id).or_default() += 1;
            }
        }
        // convert to vec and sort
        let mut by_count: Vec<(usize, usize)> = entry_counts.into_iter().collect();
        by_count.sort_by(|a, b| b.1.cmp(&a.1)); // descending

        // build mapping from old entry id to new entry id
        let mut entry_id_map = HashMap::new();
        for (i, (e, _)) in by_count.iter().enumerate() {
            entry_id_map.insert(*e as usize, i + 1); // new ids start at 1
        }

        // convert to arr with u64 -> u64
        let mut arr = Vec::with_capacity(self.unwind_table.len());
        for ((oid, addr), entry_opt) in &self.unwind_table {
            assert!(*oid < 0xffff);
            let entry_id = match entry_opt {
                Some(eid) => *entry_id_map.get(eid).unwrap(),
                None => 0,
            };
            let key = ((*oid as u64) << 48) | *addr;
            arr.push((key, entry_id as u64));
        }
        // try to fit as many entries as possible into 256k
        let mut target_len = 2 * 256 * 1024;
        let mut left = target_len / 12;
        let mut right = target_len / 2;
        let mut iterations = 0;
        while left < right {
            iterations += 1;
            let mid = (left + right + 1) / 2;
            println!("left {}, right {}, mid {}", left, right, mid);
            let table = match table::build(&arr[0..mid]) {
                Ok(t) => t,
                Err(_) => {
                    right = mid - 1;
                    continue;
                }
            };
            println!("  built table of size {}", table.len());
            if table.len() <= target_len {
                left = mid;
            } else {
                right = mid - 1;
            }
        }
        //let table = table::build(&arr[0..50000])?;
        println!("Final number of entries: {} after {} iterations", left, iterations);
        //println!("Final unwind table size: {}", table.len());
        Err(NoEhInfo) // XXX
    }
}

#[derive(Debug)]
pub struct ProcessMap {
    pub vm_start: u64,
    pub vm_end: u64,
    pub offset: u64,
    pub file_path: String,
}

pub fn read_process_maps(pid: u32) -> Result<Vec<ProcessMap>> {
    let path = format!("/proc/{}/maps", pid);
    let content = std::fs::read_to_string(path).map_err(FileOpenError)?;
    let mut maps = Vec::new();
    for line in content.lines() {
        let parts: Vec<&str> = line.split_ascii_whitespace().collect();
        if parts.len() < 6 {  // ignore all lines without file path
            continue;
        }
        if !parts[5].starts_with("/") {  // ignore anon mappings
            continue;
        }
        if parts[5].ends_with(" (deleted)") {  // ignore deleted files
            continue;
        }
        let addrs: Vec<&str> = parts[0].split('-').collect();
        if addrs.len() != 2 {
            continue;
        }
        let vm_start = u64::from_str_radix(addrs[0], 16).unwrap_or(0);
        let vm_end = u64::from_str_radix(addrs[1], 16).unwrap_or(0);
        let offset = u64::from_str_radix(parts[2], 16).unwrap_or(0);
        let file_path = parts[5].to_string();
        maps.push(ProcessMap {
            vm_start,
            vm_end,
            offset,
            file_path,
        });
    }
    Ok(maps)
}

#[cfg(test)]
mod tests {
    //use super::*;

    #[test]
    fn it_works() {
    }
}
