/**
 * The ForkEvent sent by forkMonitor eBPF program
 */
#[repr(C)]
struct ForkEvent{
    pid: u32,
    ppid: u32,
}

#[cfg(feature = "android_bpf")]
use libc::{bpf, BPF_OBJ_GET, BPF_PROG_ATTACH, BPF_TRACEPOINT};

#[cfg(feature = "android_bpf")]
unsafe fn attach_tracepoint() -> std::io::Result<()> {

    Ok(())
}


#[cfg(feature = "linux_bpf")]
unsafe fn attach_tracepoint() -> std::io::Result<()> {
    todo!("Not implemented for this platform yet")
}



pub(crate) struct Scanner{
    /*stub*/
}


impl Scanner{
    #[cfg(feature = "linux_bpf")]
    pub unsafe fn run(){
        todo!()
    }

    #[cfg(feature = "android_bpf")]
    pub unsafe fn run(){

    }
}