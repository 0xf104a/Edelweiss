use crate::bpf;
use crate::bpf::BpfProbeAttachType;

pub(super) unsafe fn attach_tracepoint(prog_fd: i32, category: &str, point: &str){
    log::info!("Attach tracepoint {}/{} to FD {}", category, point, prog_fd);
    #[cfg(feature = "android_bpf")]
    {
        let ret =
            bpf::bpf_attach_tracepoint(prog_fd, category.as_ptr() as *const i8, point.as_ptr() as *const i8);
        log::debug!("complete: attach tracepoint {}/{}: {}", category, point, ret);
        std::thread::sleep(std::time::Duration::from_secs(5));
    }
}

pub(super) unsafe fn attach_kprobe(prog_fd: i32, attach_type: BpfProbeAttachType, ev_name: &str,
                                   fn_name: &str, fn_offset: u64, maxactive: i32){
    log::info!("Attach kprobe {}/{}@{} to FD {}", ev_name, fn_name, fn_offset, prog_fd);
    #[cfg(feature = "android_bpf")]
    {
        let ret = bpf::bpf_attach_kprobe(prog_fd, attach_type, ev_name.as_ptr() as *const i8,
                                         fn_name.as_ptr() as *const i8, fn_offset, maxactive);
        log::debug!("complete: attach kprobe {}/{}@{}: {}", ev_name, fn_name, fn_offset, ret);
        std::thread::sleep(std::time::Duration::from_secs(5));
    }
}