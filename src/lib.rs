use object::{Object, ObjectSection};
use gimli::UnwindSection;
use thiserror::Error;
use std::collections::{ HashMap, BTreeMap };
use log::{ debug, info, warn };

const NUM_REGISTERS: usize = 17; // r0 - r15 + pc
const CFT_ENTRY_SIZE: usize = 228;
const MAX_MAPPINGS: usize = 1000;
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
    #[error("Object table is full")]
    TooManyObjects,
    #[error("Can't encode table value")]
    TableValueEncodeError,
    #[error("Can't encode table ptr")]
    TablePtrEncodeError,
    #[error("Can't decode table value")]
    TableValueDecodeError,
    #[error("Table build error")]
    TableBuildError,
    #[error("Table not yet built")]
    TableNotBuilt,
    #[error("PID not found")]
    PidNotFound,

}
use FswError::*;

type Result<T> = std::result::Result<T, FswError>;

/*
#[derive(Debug)]
struct EvaluationContext {
    address_size: usize,
    dwarf_version: usize,
    dwarf64: bool,
}
*/

#[derive(Debug)]
pub struct Fsw {
    unwind_tables: Vec<BTreeMap<u64, Option<usize>>>,
    unwind_entries: BTreeMap<usize, Vec<u8>>,   // XXX needed? only rev?
    unwind_entry_counts: Vec<usize>,
    unwind_entries_rev: BTreeMap<Vec<u8>, usize>,
    expressions: BTreeMap<usize, Vec<u8>>,  // XXX needed? only rev?
    expressions_rev: BTreeMap<Vec<u8>, usize>,
    total_eh_frame_size: usize,
    table_mappings: HashMap<usize, Vec<(u64, usize, usize)>>, // oid -> ( table id, offset)
    pid_map: HashMap<u32, Vec<ProcessMap>>, // pid -> maps
    files_seen: HashMap<String, Option<usize>>, // file path -> oid
}

#[derive(Debug, PartialEq, Eq, Hash)]
pub enum ParsingError {
    NoError,
    BadExpressionOffset,
    UnknownRegisterRule,
    RowOverlap,
}

impl Fsw {
    pub fn new() -> Self {
        Fsw {
            unwind_tables: Vec::new(),
            unwind_entries: BTreeMap::new(),
            unwind_entries_rev: BTreeMap::new(),
            unwind_entry_counts: Vec::new(),
            expressions: BTreeMap::new(),
            expressions_rev: BTreeMap::new(),
            total_eh_frame_size: 0,
            table_mappings: HashMap::new(),
            pid_map: HashMap::new(),
            files_seen: HashMap::new(),
        }
    }

    // oid object id must be unique
    pub fn add_file<P: AsRef<std::path::Path>>(&mut self, path: P)
        -> Result<(usize, HashMap<ParsingError, u64>)>
    { 
        let oid = self.unwind_tables.len();
        if oid == u16::MAX as usize {
            return Err(TooManyObjects);
        }
        let file = std::fs::File::open(path).map_err(FileOpenError)?;

        let mmap = unsafe { memmap2::Mmap::map(&file).map_err(MmapError)? };
        let object = object::File::parse(&*mmap).map_err(ObjectParseError)?;

        let eh_frame_section = object
            .section_by_name(".eh_frame")
            .ok_or(NoEhInfo)?;

        let mut unwind_table = BTreeMap::new();
        let mut parsing_errors = HashMap::new();
        let eh_frame_data = eh_frame_section.uncompressed_data().map_err(ObjectParseError)?;
        debug!("Parsing .eh_frame of size {}", eh_frame_data.len());
        self.total_eh_frame_size += eh_frame_data.len();
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
                        let mut s = Vec::new();
                        // serialize row into the format used by our eBPF program
                        let saved_args_size = row.saved_args_size() as u64;
                        s.extend_from_slice(&saved_args_size.to_le_bytes());

                        match row.cfa() {
                            gimli::CfaRule::RegisterAndOffset { register, offset } => {
                                let reg = register.0 as u32;
                                let off = *offset as i64;
                                s.extend_from_slice(&1u32.to_le_bytes());
                                s.extend_from_slice(&reg.to_le_bytes());
                                s.extend_from_slice(&off.to_le_bytes());
                            }
                            gimli::CfaRule::Expression(e) => {
                                if e.offset + e.length > eh_frame_data.len() {
                                    break 'rows;
                                }
                                let expr_id = self.add_expression(Vec::from(&eh_frame_data
                                    [e.offset .. e.offset + e.length]));
                                let expr_id = expr_id as u32;
                                s.extend_from_slice(&2u32.to_le_bytes());
                                s.extend_from_slice(&expr_id.to_le_bytes());
                                s.extend_from_slice(&[0u8; 8]);
                            }
                        }
                        // convert registers
                        let mut rules_s = Vec::new();
                        for (reg, rule) in row.registers() {
                            let mut rs = Vec::new();
                            match rule {
                                gimli::RegisterRule::Undefined => {
                                    rs.extend_from_slice(&1u32.to_le_bytes());
                                    rs.extend_from_slice(&[0u8; 8]);
                                }
                                gimli::RegisterRule::SameValue => {
                                    rs.extend_from_slice(&2u32.to_le_bytes());
                                    rs.extend_from_slice(&[0u8; 8]);
                                }
                                gimli::RegisterRule::Offset(o) => {
                                    let off = *o as i64;
                                    rs.extend_from_slice(&3u32.to_le_bytes());
                                    rs.extend_from_slice(&off.to_le_bytes());
                                }
                                gimli::RegisterRule::ValOffset(o) => {
                                    let off = *o as i64;
                                    rs.extend_from_slice(&4u32.to_le_bytes());
                                    rs.extend_from_slice(&off.to_le_bytes());
                                }
                                gimli::RegisterRule::Register(r) => {
                                    let reg = r.0 as u64;
                                    rs.extend_from_slice(&5u32.to_le_bytes());
                                    rs.extend_from_slice(&reg.to_le_bytes());
                                },
                                gimli::RegisterRule::Expression(e) => {
                                    if e.offset + e.length > eh_frame_data.len() {
                                        error = ParsingError::BadExpressionOffset;
                                        break 'rows;
                                    }
                                    let expr_id = self.add_expression(Vec::from(&eh_frame_data
                                        [e.offset .. e.offset + e.length]));
                                        let expr_id = expr_id as u64;
                                        rs.extend_from_slice(&6u32.to_le_bytes());
                                        rs.extend_from_slice(&expr_id.to_le_bytes());
                                }
                                gimli::RegisterRule::ValExpression(e) => {
                                    if e.offset + e.length > eh_frame_data.len() {
                                        error = ParsingError::BadExpressionOffset;
                                        break 'rows;
                                    }
                                    let expr_id = self.add_expression(Vec::from(&eh_frame_data
                                        [e.offset .. e.offset + e.length]));
                                    rs.extend_from_slice(&7u32.to_le_bytes());
                                    rs.extend_from_slice(&expr_id.to_le_bytes());
                                }
                                gimli::RegisterRule::Architectural => {
                                    rs.extend_from_slice(&8u32.to_le_bytes());
                                    rs.extend_from_slice(&[0u8; 8]);
                                }
                                gimli::RegisterRule::Constant(c) => {
                                    let c = *c as u64;
                                    rs.extend_from_slice(&9u32.to_le_bytes());
                                    rs.extend_from_slice(&c.to_le_bytes());
                                }
                                _ => {
                                    error = ParsingError::UnknownRegisterRule;
                                    break 'rows;
                                }
                            };
                            rules_s.push((reg.0, rs));
                        }

                        for i in 0 .. NUM_REGISTERS as u16 {
                            if let Some((_, rule)) = rules_s.iter().find(|(r, _)| *r == i) {
                                s.extend_from_slice(rule);
                            } else {
                                // uninitialized
                                s.extend_from_slice(&0u32.to_le_bytes());
                                s.extend_from_slice(&[0u8; 8]);
                            }
                        }
                        assert_eq!(s.len(), CFT_ENTRY_SIZE);

                        // get row index or create new
                        let entryid = if let Some(id) = self.unwind_entries_rev.get(&s) {
                            self.unwind_entry_counts[*id] += 1;
                            *id
                        } else {
                            let id = self.unwind_entries.len();
                            self.unwind_entries.insert(id, s.clone());
                            self.unwind_entries_rev.insert(s, id);
                            self.unwind_entry_counts.push(1);
                            id
                        };
                        // start may override end
                        // start may not override start
                        // end overrides nothing
                        let start = row.start_address();
                        let end = row.end_address();
                        if let Some(Some(_)) = unwind_table.get(&start) {
                            error = ParsingError::RowOverlap;
                            break 'rows;
                        }
                        unwind_table.insert(start, Some(entryid));
                        if unwind_table.get(&end).is_none() {
                            unwind_table.insert(end, None);
                        }
                    }
                    if error != ParsingError::NoError {
                        *parsing_errors.entry(error).or_default() += 1;
                    }
                }
            }
        }
        warn!("Parsing errors: {:?}", parsing_errors);
        info!("Unwind entries: {}", self.unwind_entries.len());
        info!("Unwind table  : {}", unwind_table.len());
        info!("Expressions   : {}", self.expressions.len());

        self.unwind_tables.push(unwind_table);

        Ok((oid, parsing_errors))
    }

    // returns vec of (vma_start, file-offset, offsetmap_id, start-in-map)
    pub fn build_mapping_for_pid(&mut self, pid: u32)
        -> Result<Vec<u8>>
    {
        let Some(maps) = self.pid_map.get(&pid) else {
            return Err(FswError::PidNotFound);
        };
        let mut s = vec![0u8; 8]; // reserve space for number of entries
        let mut num_entries = 0;
        for map in maps.iter() {
            let Some(Some(oid)) = self.files_seen.get(&map.file_path) else {
                continue;
            };
            let Some(mapping) = self.table_mappings.get(oid) else {
                println!("No mapping found for oid {}", oid);
                break;
            };
            let map_offset_end = map.offset + (map.vm_end - map.vm_start);
            for (file_offset, table_id, table_offset) in mapping.iter() {
                if *file_offset >= map_offset_end {
                    break;
                }
                if *file_offset < map.offset {
                    continue;
                }
                let delta = *file_offset - map.offset;

                let start = (map.vm_start + delta) as u64;
                let offset = (map.offset + delta) as u64;
                let table_id = *table_id as u32;
                let table_offset = *table_offset as u32;

                s.extend_from_slice(&start.to_le_bytes());
                s.extend_from_slice(&offset.to_le_bytes());
                s.extend_from_slice(&table_id.to_le_bytes());
                s.extend_from_slice(&table_offset.to_le_bytes());

                num_entries += 1;
            }
        }
        // prepend number of entries
        let num_entries_u64 = num_entries as u64;
        s[0..8].copy_from_slice(&num_entries_u64.to_le_bytes());
        // fill up to expected size
        s.extend(vec![0u8; (MAX_MAPPINGS - num_entries) * 24]);

        Ok(s)
    }

    pub fn add_pid(&mut self, pid: u32) -> Result<()> {
        if self.pid_map.contains_key(&pid) {
            return Ok(());
        }
        let maps = read_process_maps(pid)?;
        for map in &maps {
            if self.files_seen.contains_key(&map.file_path) {
                continue;
            }
            let res = self.add_file(&map.file_path);
println!("Adding file: {} result {:?}", map.file_path, res);
            let oid = match res {
                Ok((oid, _errors)) => Some(oid),
                Err(_) => None,
            };
            self.files_seen.insert(map.file_path.clone(), oid);
        }
        self.pid_map.insert(pid, maps);

        Ok(())
    }

    fn add_expression(&mut self, expr: Vec<u8>) -> usize {
        debug!("expression: {:?}", expr);
        if let Some(id) = self.expressions_rev.get(&expr) {
            *id
        } else {
            let id = self.expressions.len();
            self.expressions.insert(id, expr.clone());
            self.expressions_rev.insert(expr, id);
            id
        }
    }

    pub fn build_tables(&mut self)
        -> Result<(
             Vec<Vec<u8>>,       // unwind tables
             Vec<Vec<u8>>,       // unwind entries
             Vec<Vec<u8>>,       // expressions
           )>
    {
        let mut tables = Vec::new();
        let mut mappings: HashMap<usize, Vec<(u64, usize, usize)>>  = HashMap::new();
        let chunk_size = 256 * 1024; // 256 KB per eBPF map entry

        // count occurences of unwind entries and sort them in descending order, so that
        // the entries with the highest occurences get the lowest ids for a smaller encoding
        let mut by_count: Vec<(usize, usize)> = self.unwind_entry_counts.iter().enumerate()
            .map(|(i, c)| (i, *c)).collect();
        by_count.sort_by(|a, b| b.1.cmp(&a.1));

        // build map from old entry id to new entry id
        let mut entry_id_map = vec![0; by_count.len()];
        for (new_id, (old_id, _count)) in by_count.iter().enumerate() {
            entry_id_map[*old_id] = new_id;
        }

        let mut current_table = Vec::new();
        let mut current_table_id = 0;
        for (oid, unwind_table) in self.unwind_tables.iter().enumerate() {
            // convert unwind table to arr with u64 -> u64
            let mut arr = Vec::with_capacity(unwind_table.len());
            for (addr, entry_opt) in unwind_table {
                let entry_id = match entry_opt {
                    Some(eid) => entry_id_map[*eid] + 1, // entry ids start at 1
                    None => 0,                           // 0 means end of unwind info
                };
                arr.push((*addr, entry_id as u64));
            }
            //println!("Final unwind table size: {}", table.len());

            let mut start = 0;
            while arr.len() > start {
                let sz = chunk_size - current_table.len() - 16; // leave some space to relax bounds
                                                                // checks in eBPF
                let (table, entries) = table::build(&arr[start..], sz)?;
println!("add mapping: oid {} addr {:x} table id {} offset {}",
    oid, arr[start].0, current_table_id, current_table.len());
                let entry = mappings.entry(oid).or_default();
                entry.push((arr[start].0, current_table_id, current_table.len()));
                if current_table.is_empty() {
                    current_table = table;
                } else {
                    current_table.extend_from_slice(&table);
                }
                if current_table.len() >= chunk_size - 200 {
                    tables.push(current_table);
                    current_table = Vec::new();
                    current_table_id += 1;
                }
                start += entries;
            }
        }

        if !current_table.is_empty() {
            current_table.extend(vec![0u8; chunk_size - current_table.len()]); // pad end
            tables.push(current_table);
        }
        println!("Final unwind table size: {} in {} parts",
            tables.iter().map(|t| t.len()).sum::<usize>(), tables.len());
        println!("Total .eh_frame size: {}", self.total_eh_frame_size);
        println!("number of unwind tables: {}", self.unwind_tables.len());
        println!("Total unwind entries: {}",
            self.unwind_tables.iter().map(|u| u.len()).sum::<usize>());
        println!("Unique unwind entries: {}", self.unwind_entries.len());

        let mut entries = Vec::new();
        entries.push(vec![0u8; CFT_ENTRY_SIZE]); // entry id 0 means no unwind info
        for (old_id, _) in by_count.iter() {
            let entry = self.unwind_entries.get(old_id).unwrap();
            entries.push(entry.clone());
        }

        // XXX TODO: build as vector in the first place
        let mut exprs = Vec::new();
        for (id, expr) in self.expressions.iter() {
            assert_eq!(*id, exprs.len());
            assert!(expr.len() < 256);
            let mut e = expr.clone();
            e.extend_from_slice(&[e.len() as u8; 1]);
            e.extend(vec![0u8; 255 - expr.len()]); // align to 16 bytes
            exprs.push(e);
        }

        self.table_mappings = mappings;

        Ok((tables, entries, exprs))
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
println!("map: {:x}-{:x} offset {:x} file {}", vm_start, vm_end, offset, file_path);
        maps.push(ProcessMap {
            vm_start,
            vm_end,
            offset,
            file_path,
        });
    }
    Ok(maps)
}
