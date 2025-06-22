use crate::bpf;
use crate::bpf::ring_buffer__poll;
use crate::bpf::streamer::{Streamer, StreamerNotifier};
use libc::close;
use std::ffi::CString;
use std::marker::PhantomData;
use std::mem::MaybeUninit;
use std::ptr::{null, null_mut};
use crate::utils::tokio::init_tokio;

#[derive(Clone)]
pub(crate) struct RingBufferStreamer<
    K: Clone + Send + Sync,
    T: StreamerNotifier<K> + Clone + Send + Sync,
> {
    bpf_tp_prog_path: String,
    bpf_map_path: String,
    bpf_tp_category: String,
    bpf_tp_name: String,
    consumer: T,
    phantom_data: PhantomData<K>,
}

impl<K: Clone + Send + Sync, T: StreamerNotifier<K> + Clone + Send + Sync>
    RingBufferStreamer<K, T>
{
    pub fn new(
        bpf_tp_prog_path: String,
        bpf_map_path: String,
        bpf_tp_category: String,
        bpf_tp_name: String,
        consumer: T,
    ) -> Self {
        RingBufferStreamer {
            bpf_tp_prog_path,
            bpf_map_path,
            bpf_tp_category,
            bpf_tp_name,
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
        let prog_path = CString::new(self.bpf_tp_prog_path.clone()).expect("CString::new failed");
        let map_path = CString::new(self.bpf_map_path.clone()).expect("CString::new failed");
        let category = CString::new(self.bpf_tp_category.clone()).expect("CString::new failed");
        let point = CString::new(self.bpf_tp_name.clone()).expect("CString::new failed");
        let prog_fd = bpf::bpf_obj_get(prog_path.as_ptr());
        if prog_fd == 0 {
            panic!("bpf_obj_get failed on prog");
        }
        let map_fd = bpf::bpf_obj_get(map_path.as_ptr());
        log::trace!("map_fd={}, path={}", map_fd, self.bpf_map_path);
        if map_fd == 0 {
            panic!("bpf_obj_get failed on map");
        }
        #[cfg(feature = "android_bpf")]
        {
            let ret =
                bpf::bpf_attach_tracepoint(prog_fd, category.as_ptr(), point.as_ptr());
            std::thread::sleep(std::time::Duration::from_secs(5));
        }

        let consumer_box: Box<T> = Box::new(self.consumer.clone());
        let consumer_ptr = Box::into_raw(consumer_box) as *mut std::ffi::c_void;
        log::trace!("ctx={:?}", consumer_ptr);
        let rb = bpf::ring_buffer__new(
            map_fd,
            Some(RingBufferStreamer::<K, T>::handle_event),
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

impl<K: Clone + Send + Sync + 'static, T: StreamerNotifier<K> + Clone + Send + Sync + 'static>
    Streamer<K> for RingBufferStreamer<K, T>
{
    fn start(&mut self) {
        let mut m_copy = self.clone();
        std::thread::spawn(move || unsafe {
            init_tokio();
            m_copy.run();
        });
    }
}
