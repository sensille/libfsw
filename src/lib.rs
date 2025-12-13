use object::{Object, ObjectSection};
use gimli::{ UnwindSection, Register };
use thiserror::Error;
use std::collections::HashMap;
use std::collections::BTreeMap;

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
    unwind_table: BTreeMap<u64, Option<usize>>,
    unwind_entries: BTreeMap<usize, UnwindEntry>,
    unwind_entries_rev: BTreeMap<UnwindEntry, usize>,
    maps: BTreeMap<u64, EvaluationContext>, // XXX
    expressions: BTreeMap<usize, Vec<u8>>,
    expressions_rev: BTreeMap<Vec<u8>, usize>,
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
        }
    }

    pub fn add_file<P: AsRef<std::path::Path>>(&mut self, path: P) -> Result<()> {
        let file = std::fs::File::open(path).map_err(FileOpenError)?;

        let mmap = unsafe { memmap2::Mmap::map(&file).map_err(MmapError)? };
        let object = object::File::parse(&*mmap).map_err(ObjectParseError)?;

        let eh_frame_section = object
            .section_by_name(".eh_frame")
            .ok_or(NoEhInfo)?;

        let eh_frame_data = eh_frame_section.uncompressed_data().map_err(ObjectParseError)?;
        let eh_frame = gimli::EhFrame::new(&eh_frame_data, gimli::NativeEndian);
        let bases = gimli::BaseAddresses::default()
            .set_eh_frame(eh_frame_section.address());
        let mut entries = eh_frame.entries(&bases);
        let mut cies = HashMap::new();
        let mut unwind_ctx = gimli::UnwindContext::new();
        let mut errors: HashMap<ParsingError, u64> = HashMap::new();
        while let Some(entry) = entries.next().map_err(GimliError)? {
            match entry {
                gimli::CieOrFde::Cie(cie) => {
                    println!("Found CIE: offset {:x}", cie.offset());
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
                            let id = self.unwind_entries.len();
                            self.unwind_entries.insert(id, entry.clone());
                            self.unwind_entries_rev.insert(entry, id);
                            id
                        };
                        // start may override end
                        // start may not override start
                        // end overrides nothing
                        if let Some(Some(_)) = self.unwind_table.get(&row.start_address()) {
                            error = ParsingError::RowOverlap;
                            break 'rows;
                        }
                        self.unwind_table.insert(row.start_address(), Some(entryid));
                        if self.unwind_table.get(&row.end_address()).is_none() {
                            self.unwind_table.insert(row.end_address(), None);
                        }
                    }
                    if error != ParsingError::NoError {
                        *errors.entry(error).or_default() += 1;
                    }
                }
            }
        }
        println!("Parsing errors: {:?}", errors);
        println!("Unwind entries: {}", self.unwind_entries.len());
        println!("Unwind table  : {}", self.unwind_table.len());
        println!("Expressions   : {}", self.expressions.len());
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
    }
}
