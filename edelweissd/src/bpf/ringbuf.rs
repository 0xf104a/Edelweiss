use crate::bpf;
use crate::bpf::{ring_buffer__poll, BpfProbeAttachType};
use crate::bpf::streamer::{Streamer, StreamerNotifier};
use libc::close;
use std::ffi::CString;
use std::marker::PhantomData;
use std::mem::MaybeUninit;
use std::ptr::{null, null_mut};
use crate::bpf::attach::{attach_kprobe, attach_tracepoint};
use crate::utils::tokio::init_tokio;

pub trait AttachPoint: Clone + Send + Sync{
    ///
    /// Attaches to point(e.g. tracepoint, krpobe)
    /// Returns map file descriptor
    ///
    unsafe fn attach(&self) -> i32;
}

#[derive(Clone)]
pub(crate) struct RingBufferTracepoint{
    bpf_tp_prog_path: String,
    bpf_map_path: String,
    bpf_prog_category: String,
    bpf_prog_point: String,
}

#[derive(Clone)]
pub(crate) struct RingBufferKprobePoint {
    kprobe_prog: String,
    kprobe_attach_type: BpfProbeAttachType,
    kprobe_event: String,
    kprobe_func: String,
    kprobe_offset: u64,
    kprobe_maxactive: i32,
    kprobe_map: String,
}

impl RingBufferTracepoint {
    pub fn new(bpf_tp_prog_path: &str, bpf_map_path: &str,
               bpf_prog_category: &str, bpf_prog_point: &str) -> Self {
        RingBufferTracepoint {
            bpf_map_path: bpf_map_path.to_string(),
            bpf_tp_prog_path: bpf_tp_prog_path.to_string(),
            bpf_prog_category: bpf_prog_category.to_string(),
            bpf_prog_point: bpf_prog_point.to_string(),
        }
    }
}

impl AttachPoint for RingBufferTracepoint{
    unsafe fn attach(&self) -> i32 {
        log::debug!("Attaching tracepoint {}, map {}", self.bpf_tp_prog_path, self.bpf_map_path);
        let prog_path = CString::new(self.bpf_tp_prog_path.clone()).expect("CString::new failed");
        let map_path = CString::new(self.bpf_map_path.clone()).expect("CString::new failed");
        let prog_fd = bpf::bpf_obj_get(prog_path.as_ptr());
        if prog_fd == 0 {
            panic!("bpf_obj_get failed on prog");
        }
        let map_fd = bpf::bpf_obj_get(map_path.as_ptr());
        log::trace!("map_fd={}, path={}", map_fd, self.bpf_map_path);
        if map_fd == 0 {
            panic!("bpf_obj_get failed on map");
        }
        attach_tracepoint(prog_fd, self.bpf_prog_category.as_str(), self.bpf_prog_point.as_str());
        map_fd
    }
}

impl RingBufferKprobePoint{
    pub fn new(kprobe_prog: &str, kprobe_attach_type: BpfProbeAttachType, kprobe_event: &str,
               kprobe_func: &str, kprobe_offset: u64, kprobe_maxactive: i32, kprobe_map: &str) -> Self {
        Self{
            kprobe_prog: kprobe_prog.to_string(),
            kprobe_attach_type,
            kprobe_event: kprobe_event.to_string(),
            kprobe_func: kprobe_func.to_string(),
            kprobe_offset,
            kprobe_map: kprobe_map.to_string(),
            kprobe_maxactive,
        }
    }
}

impl AttachPoint for RingBufferKprobePoint{
    unsafe fn attach(&self) -> i32 {
        log::debug!("Attaching kpropbe {}, map {}", self.kprobe_prog, self.kprobe_map);
        let prog_path = CString::new(self.kprobe_prog.clone()).expect("CString::new failed");
        let map_path = CString::new(self.kprobe_map.clone()).expect("CString::new failed");
        let prog_fd = bpf::bpf_obj_get(prog_path.as_ptr());
        if prog_fd == 0 {
            panic!("bpf_obj_get failed on prog");
        }
        let map_fd = bpf::bpf_obj_get(map_path.as_ptr());
        log::trace!("map_fd={}, path={}", map_fd, self.kprobe_map);
        if map_fd == 0 {
            panic!("bpf_obj_get failed on map");
        }
        attach_kprobe(prog_fd, self.kprobe_attach_type, self.kprobe_event.as_str(),
                      self.kprobe_func.as_str(), self.kprobe_offset, self.kprobe_maxactive);
        map_fd
    }
}

///
/// Basic streamer for kernel ring buffer.
/// Attaches to all points and streams data from single map.
/// **Note:** All tracepoint should return same map fd
///
#[derive(Clone)]
pub(crate) struct RingBufferStreamer<
    K: Clone + Send + Sync,
    T: StreamerNotifier<K> + Clone + Send + Sync,
    P: AttachPoint,
> {
    points: Vec<P>,
    consumer: T,
    phantom_data: PhantomData<K>,
}

impl<K: Clone + Send + Sync, T: StreamerNotifier<K> + Clone + Send + Sync, P: AttachPoint>
    RingBufferStreamer<K, T, P>
{
    pub fn new(
        points: Vec<P>,
        consumer: T,
    ) -> Self {
        RingBufferStreamer {
            points,
            consumer,
            phantom_data: PhantomData,
        }
    }

    unsafe extern "C" fn handle_event(
        ctx: *mut std::ffi::c_void,
        data: *mut std::ffi::c_void,
        data_sz: libc::size_t,
    ) -> std::ffi::c_int {
        if data_sz < std::mem::size_of::<T>() {
            return 0;
        }

        let consumer = &mut *(ctx as *mut T);
        let src_ptr = data as *const K;

        let mut boxed: Box<MaybeUninit<K>> = Box::new_uninit();
        std::ptr::copy_nonoverlapping(src_ptr, boxed.as_mut_ptr(), 1);
        let boxed_k: Box<K> = boxed.assume_init();

        let unboxed = *boxed_k;

        consumer.notify(unboxed);
        0
    }

    #[allow(unused)]
    unsafe fn run(&mut self) {
        let mut map_fd = 0;
        for point in &self.points {
            let new_map_fd = point.attach();
            if new_map_fd != map_fd && map_fd != 0{
                panic!("All points should return same map fd for RingBufferStreamer");
            }
            map_fd = new_map_fd;
        }
        let consumer_box: Box<T> = Box::new(self.consumer.clone());
        let consumer_ptr = Box::into_raw(consumer_box) as *mut std::ffi::c_void;

        log::trace!("ctx={:?}", consumer_ptr);
        let rb = bpf::ring_buffer__new(
            map_fd,
            Some(RingBufferStreamer::<K, T, P>::handle_event),
            consumer_ptr,
            null(),
        );

        log::debug!("Start epoll");
        loop {
            let err = ring_buffer__poll(rb, -1);
            if err < 0 {
                if err == -libc::EINTR {
                    continue; // Retry on EINTR
                } else {
                    panic!("ring_buffer__poll failed({err})");
                }
            }
            log::debug!("Poll err=#{err}");
        }
    }
}

impl<K: Clone + Send + Sync + 'static, T: StreamerNotifier<K> + Clone + Send + Sync + 'static,
    P: AttachPoint + 'static>
    Streamer<K> for RingBufferStreamer<K, T, P>
{
    fn start(&mut self) {
        let mut m_copy = self.clone();
        std::thread::spawn(move || unsafe {
            init_tokio();
            m_copy.run();
        });
    }
}
