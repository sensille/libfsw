use anyhow::Result;
use libfsw::Fsw;


fn main() -> Result<()> {
    let fsw = Fsw::new();
    fsw.add_file("/usr/lib/firefox/firefox")?;

    Ok(())
}
