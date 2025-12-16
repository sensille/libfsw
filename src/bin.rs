use anyhow::Result;
use libfsw::Fsw;

fn main() -> Result<()> {
    env_logger::init();

    let mut fsw = Fsw::new();
    /*
    fsw.add_file("../fswutil/ceph-osd")?;
    fsw.build_unwind_tables()?;
    return Ok(());
    fsw.add_file("/usr/lib/libz.so.1.3.1")?;
    */
    fsw.add_pid(3694)?;
    fsw.build_unwind_tables()?;

    Ok(())
}
