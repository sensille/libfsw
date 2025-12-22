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
    let pid = 4504;
    fsw.add_file("/usr/lib/firefox/libxul.so")?;
    //fsw.add_pid(pid)?;
    fsw.build_tables()?;
    let res = fsw.lookup(pid, 0x7cd5da39a1cb);
    println!("{:?}", res);

    Ok(())
}
