use anyhow::Result;
use libfsw::Fsw;

fn main() -> Result<()> {
    env_logger::init();

    let mut fsw = Fsw::new();
    fsw.add_file("../fswutil/ceph-osd", 501)?;
    fsw.build_table()?;
    fsw.add_file("/usr/lib/libz.so.1.3.1", 500)?;
    fsw.add_pid(3694)?;

    Ok(())
}
