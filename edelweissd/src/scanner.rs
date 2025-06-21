/**
 * The ForkEvent sent by forkMonitor eBPF program
 */
#[repr(C)]
struct ForkEvent{
    pid: u32,
    ppid: u32,
}

use std::ffi::CString;
use std::ptr::{null, null_mut};
use libc::close;
use crate::bpf;
use crate::bpf::{ring_buffer__new, ring_buffer__poll, RingBuffer};

pub(crate) struct Scanner{
    r_buffer: RingBuffer,
}

#[cfg(feature = "linux_bpf")]
const BPF_MAP_PATH: &str = "/sys/fs/bpf/fork_events";
#[cfg(feature = "android_bpf")]
const BPF_MAP_PATH: &str = "/sys/fs/bpf/map_forkMonitor_fork_events";
#[cfg(feature = "linux_bpf")]
const BPF_TP_PROG_PATH: &str = "/sys/fs/bpf/pollenFork";
#[cfg(feature = "android_bpf")]
const BPF_TP_PROG_PATH: &str = "/sys/fs/bpf/prog_forkMonitor_tracepoint_sched_sched_process_fork";



impl Scanner{
    pub unsafe extern "C" fn handle_event(
        _ctx: *mut std::ffi::c_void,
        data: *mut std::ffi::c_void,
        data_sz: libc::size_t,
    ) -> std::ffi::c_int {
        if data_sz < std::mem::size_of::<ForkEvent>() {
            eprintln!("Event too small ({} bytes)", data_sz);
            return 0;
        }

        let event = &*(data as *const ForkEvent);
        println!("Fork: PID={}, PPID={}", event.pid, event.ppid);
        0
    }
    
    pub unsafe fn run() {
        let prog_path = CString::new(BPF_TP_PROG_PATH).expect("CString::new failed");
        let map_path = CString::new(BPF_MAP_PATH).expect("CString::new failed");
        let category = CString::new("sched").expect("CString::new failed");
        let point = CString::new("sched_process_fork").expect("CString::new failed");
        let prog_fd = bpf::bpf_obj_get(prog_path.as_ptr());
        if prog_fd == 0{
            panic!("bpf_obj_get failed on prog");
        }
        let map_fd = bpf::bpf_obj_get(map_path.as_ptr());
        if map_fd == 0{
            panic!("bpf_obj_get failed on map");
        }
        let ret = bpf::bpf_program__attach_tracepoint(prog_fd, category.as_ptr(), point.as_ptr());
        println!("bpf_attach_tracepoint ret={}", ret);
        std::thread::sleep(std::time::Duration::from_secs(5));
        
        let rb = bpf::ring_buffer__new(map_fd, Some(Scanner::handle_event), null_mut(), null());
        println!("Start epoll");
        loop {
            let err = ring_buffer__poll(rb, -1);
            if err < 0 && err != -libc::EINTR {
                panic!("ring_buffer__poll failed({err})");
            } else if err == libc::EINTR { 
                break;
            }
            println!("Poll err=#{err}");
        }
        println!("Loop terminated");
        bpf::ring_buffer__free(rb);
        close(map_fd);
    }
}
