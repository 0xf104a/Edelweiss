pub mod streamer;
pub mod ringbuf;

use libc::{epoll_event, size_t};

pub type RingBufferSampleFn = Option<unsafe extern "C" fn(ctx: *mut std::ffi::c_void, data: *mut std::ffi::c_void, size: size_t) -> std::ffi::c_int>;

#[repr(C)]
pub(crate) struct Ring {
    pub sample_cb: RingBufferSampleFn,
    pub ctx: *mut std::ffi::c_void,
    pub data: *mut std::ffi::c_void,
    pub consumer_pos: *mut libc::c_ulong,
    pub producer_pos: *mut libc::c_ulong,
    pub mask: libc::c_ulong,
    pub map_fd: std::ffi::c_int,
}

#[repr(C)]
#[derive(Clone)]
pub(crate) struct RingBuffer {
    pub events: *mut epoll_event,
    pub rings: *mut *mut Ring,
    pub page_size: size_t,
    pub epoll_fd: std::ffi::c_int,
    pub ring_cnt: std::ffi::c_int,
}

#[repr(C)]
pub(crate) struct RingBufferOpts {
    pub sz: size_t,
}

#[link(name = "bpf")]
extern "C" {
    pub fn bpf_obj_get(pathname: *const std::ffi::c_char) -> i32;
    pub fn bpf_map_lookup_elem(fd: i32, key: *const std::ffi::c_void, value: *mut std::ffi::c_void) -> i32;
    pub fn ring_buffer__new(
        map_fd: std::ffi::c_int,
        sample_cb: RingBufferSampleFn,
        ctx: *mut std::ffi::c_void,
        opts: *const RingBufferOpts,
    ) -> *mut RingBuffer;
    
    pub fn ring_buffer__free(rb: *mut RingBuffer);

    pub fn ring_buffer__poll(rb: *mut RingBuffer, timeout_ms: std::ffi::c_int) -> std::ffi::c_int;
}

#[cfg(feature = "android_bpf")]
#[link(name = "bpf_bcc")]
extern "C" {
    pub fn bpf_attach_tracepoint(progfd: i32, tp_category: *const std::ffi::c_char, tp_name: *const std::ffi::c_char) -> i32;
}

