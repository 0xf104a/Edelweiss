use crate::bpf;

pub(super) unsafe fn attach_tracepoint(prog_fd: i32, category: &str, point: &str){
    log::info!("Attach tracepoint {}/{} to FD {}", category, point, prog_fd);
    #[cfg(feature = "android_bpf")]
    {
        let ret =
            bpf::bpf_attach_tracepoint(prog_fd, category.as_ptr(), point.as_ptr());
        log::debug!("attach tracepoint {}/{}: {}", category, point, ret);
        std::thread::sleep(std::time::Duration::from_secs(5));
    }
}