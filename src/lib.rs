use object::{Object, ObjectSection};
use gimli::UnwindSection;
use thiserror::Error;
use std::collections::HashMap;

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
    #[error("Gimli error")]
    GimliError(gimli::Error),
    #[error("CIE missing for FDE")]
    MissingCie,

}
use FswError::*;

type Result<T> = std::result::Result<T, FswError>;

pub struct Fsw {
}

impl Fsw {
    pub fn new() -> Self {
        Fsw {}
    }
    pub fn add_file<P: AsRef<std::path::Path>>(&self, path: P) -> Result<()> {
        let file = std::fs::File::open(path).map_err(FileOpenError)?;

        // SAFETY: This is not safe. `gimli` does not mitigate against modifications to the
        // file while it is being read. See the `memmap2` documentation and take your own
        // precautions. `fs::read` could be used instead if you don't mind loading the entire
        // file into memory.
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
        while let Some(entry) = entries.next().map_err(GimliError)? {
            match entry {
                gimli::CieOrFde::Cie(cie) => {
                    println!("Found CIE: offset {:x}", cie.offset());
                    cies.insert(cie.offset(), cie);
                }
                gimli::CieOrFde::Fde(partial_fde) => {
                    let fde = partial_fde.parse(
                        |_, _, o| {
                            println!("want offset {:?}", o);
                            if let Some(cie) = cies.get(&o.0) {
                                Ok(cie.clone())
                            } else {
                                Err(gimli::read::Error::Io)
                            }
                        })
                        .map_err(GimliError)?;

                    let mut table = fde.rows(&eh_frame, &bases, &mut unwind_ctx)
                        .map_err(GimliError)?;
                    while let Some(row) = table.next_row().map_err(GimliError)? {
                        println!("FDE row: {:?}", row);
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
    }
}
