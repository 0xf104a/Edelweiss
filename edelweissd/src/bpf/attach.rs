use crate::bpf;

pub(super) unsafe fn attach_tracepoint(prog_fd: i32, category: &str, point: &str){
    log::info!("Attach tracepoint {}/{} to FD {}", category, point, prog_fd);
    #[cfg(feature = "android_bpf")]
    {
        let ret =
            bpf::bpf_attach_tracepoint(prog_fd, category.as_ptr() as *const i8, point.as_ptr() as *const i8);
        log::debug!("attach tracepoint {}/{}: {}", category, point, ret);
        std::thread::sleep(std::time::Duration::from_secs(5));
    }
}
