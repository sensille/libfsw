use anyhow::Result;
use libfsw::Fsw;


fn main() -> Result<()> {
    let mut fsw = Fsw::new();
    fsw.add_file("/usr/lib/firefox/firefox")?;
    fsw.add_file("../fswutil/ceph-osd")?;

    Ok(())
}
