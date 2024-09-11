#![no_std]

use core::ffi::c_char;
use core::ffi::c_int;
use core::ffi::c_uint;
use core::ffi::c_void;
use core::usize;

#[no_mangle]
pub extern "C" fn u_getuid_ocall() -> u32 {
    0
}

#[no_mangle]
pub extern "C" fn u_environ_ocall() -> *const *const c_char {
    core::ptr::null()
}

#[no_mangle]
pub extern "C" fn u_getenv_ocall(_name: *const c_char) -> *const c_char {
    core::ptr::null()
}

#[no_mangle]
pub extern "C" fn u_setenv_ocall(
    _error: *mut c_int,
    _name: *const c_char,
    _value: *const c_char,
    _overwrite: c_int,
) -> c_int {
    0
}

#[no_mangle]
pub extern "C" fn u_unsetenv_ocall(_error: *mut c_int, _name: *const c_char) -> c_int {
    0
}

#[no_mangle]
pub extern "C" fn u_getcwd_ocall(
    _error: *mut c_int,
    _buf: *mut c_char,
    _size: usize,
) -> *mut c_char {
    core::ptr::null_mut()
}

#[no_mangle]
pub extern "C" fn u_getpwuid_r_ocall(
    _uid: u32,
    _pwd: *mut c_char,
    _buf: *mut c_char,
    _buflen: usize,
    _passwd_result: *mut *mut c_char,
) -> c_int {
    0
}

#[no_mangle]
pub extern "C" fn u_chdir_ocall(_error: *mut c_int, _dir: *const c_char) -> c_int {
    0
}

#[no_mangle]
pub extern "C" fn u_fstatat64_ocall(
    _error: *mut c_int,
    _dirfd: c_int,
    _pathname: *const c_char,
    _buf: *mut c_char,
    _flags: c_int,
) -> c_int {
    0
}

#[no_mangle]
pub extern "C" fn u_dirfd_ocall(_error: *mut c_int, _dirp: *mut c_char) -> c_int {
    0
}

#[no_mangle]
pub extern "C" fn u_closedir_ocall(_error: *mut c_int, _dirp: *mut c_char) -> c_int {
    0
}

#[no_mangle]
pub extern "C" fn u_readdir64_r_ocall(
    _dirp: *mut c_char,
    _entry: *mut c_char,
    _result: *mut *mut c_char,
) -> c_int {
    0
}

#[no_mangle]
pub extern "C" fn u_opendir_ocall(_error: *mut c_int, _pathname: *const c_char) -> *mut c_char {
    core::ptr::null_mut()
}

#[no_mangle]
pub extern "C" fn u_fdopendir_ocall(_error: *mut c_int, _fd: c_int) -> *mut c_char {
    core::ptr::null_mut()
}

#[no_mangle]
pub extern "C" fn u_rmdir_ocall(_error: *mut c_int, _pathname: *const c_char) -> c_int {
    0
}

#[no_mangle]
pub extern "C" fn u_mkdir_ocall(_error: *mut c_int, _pathname: *const c_char, _mode: u16) -> c_int {
    0
}

#[no_mangle]
pub extern "C" fn u_realpath_ocall(_error: *mut c_int, _pathname: *const c_char) -> *mut c_char {
    core::ptr::null_mut()
}

#[no_mangle]
pub extern "C" fn u_symlink_ocall(
    _error: *mut c_int,
    _path1: *const c_char,
    _path2: *const c_char,
) -> c_int {
    0
}

#[no_mangle]
pub extern "C" fn u_readlink_ocall(
    _error: *mut c_int,
    _path: *const c_char,
    _buf: *mut c_char,
    _bufsz: usize,
) -> usize {
    0
}

#[no_mangle]
pub extern "C" fn u_chmod_ocall(_error: *mut c_int, _path: *const c_char, _mode: u16) -> c_int {
    0
}

#[no_mangle]
pub extern "C" fn u_rename_ocall(
    _error: *mut c_int,
    _oldpath: *const c_char,
    _newpath: *const c_char,
) -> c_int {
    0
}

#[no_mangle]
pub extern "C" fn u_linkat_ocall(
    _error: *mut c_int,
    _olddirfd: c_int,
    _oldpath: *const c_char,
    _newdirfd: c_int,
    _newpath: *const c_char,
    _flags: c_int,
) -> c_int {
    0
}

#[no_mangle]
pub extern "C" fn u_unlinkat_ocall(
    _error: *mut c_int,
    _dirfd: c_int,
    _pathname: *const c_char,
    _flags: c_int,
) -> c_int {
    0
}

#[no_mangle]
pub extern "C" fn u_link_ocall(
    _error: *mut c_int,
    _oldpath: *const c_char,
    _newpath: *const c_char,
) -> c_int {
    0
}

#[no_mangle]
pub extern "C" fn u_unlink_ocall(_error: *mut c_int, _pathname: *const c_char) -> c_int {
    0
}

#[no_mangle]
pub extern "C" fn u_fchmod_ocall(_error: *mut c_int, _fd: c_int, _mode: u16) -> c_int {
    0
}

#[no_mangle]
pub extern "C" fn u_fdatasync_ocall(_error: *mut c_int, _fd: c_int) -> c_int {
    0
}

#[no_mangle]
pub extern "C" fn u_fsync_ocall(_error: *mut c_int, _fd: c_int) -> c_int {
    0
}

#[no_mangle]
pub extern "C" fn u_truncate64_ocall(
    _error: *mut c_int,
    _path: *const c_char,
    _length: i64,
) -> c_int {
    0
}

#[no_mangle]
pub extern "C" fn u_truncate_ocall(
    _error: *mut c_int,
    _path: *const c_char,
    _length: i64,
) -> c_int {
    0
}

#[no_mangle]
pub extern "C" fn u_ftruncate64_ocall(_error: *mut c_int, _fd: c_int, _length: i64) -> c_int {
    0
}

#[no_mangle]
pub extern "C" fn u_ftruncate_ocall(_error: *mut c_int, _fd: c_int, _length: i64) -> c_int {
    0
}

#[no_mangle]
pub extern "C" fn u_lseek64_ocall(
    _error: *mut c_int,
    _fd: c_int,
    _offset: i64,
    _whence: c_int,
) -> i64 {
    0
}

#[no_mangle]
pub extern "C" fn u_lseek_ocall(
    _error: *mut c_int,
    _fd: c_int,
    _offset: i64,
    _whence: c_int,
) -> i64 {
    0
}

#[no_mangle]
pub extern "C" fn u_lstat64_ocall(
    _error: *mut c_int,
    _path: *const c_char,
    _buf: *mut c_char,
) -> c_int {
    0
}

#[no_mangle]
pub extern "C" fn u_lstat_ocall(
    _error: *mut c_int,
    _path: *const c_char,
    _buf: *mut c_char,
) -> c_int {
    0
}

#[no_mangle]
pub extern "C" fn u_stat64_ocall(
    _error: *mut c_int,
    _path: *const c_char,
    _buf: *mut c_char,
) -> c_int {
    0
}

#[no_mangle]
pub extern "C" fn u_stat_ocall(
    _error: *mut c_int,
    _path: *const c_char,
    _buf: *mut c_char,
) -> c_int {
    0
}

#[no_mangle]
pub extern "C" fn u_fstat64_ocall(_error: *mut c_int, _fd: c_int, _buf: *mut c_char) -> c_int {
    0
}

#[no_mangle]
pub extern "C" fn u_fstat_ocall(_error: *mut c_int, _fd: c_int, _buf: *mut c_char) -> c_int {
    0
}

#[no_mangle]
pub extern "C" fn u_openat_ocall(
    _error: *mut c_int,
    _dirfd: c_int,
    _pathname: *const c_char,
    _flags: c_int,
) -> c_int {
    0
}

#[no_mangle]
pub extern "C" fn u_open64_ocall(
    _error: *mut c_int,
    _path: *const c_char,
    _oflag: c_int,
    _mode: c_int,
) -> c_int {
    0
}

#[no_mangle]
pub extern "C" fn u_open_ocall(
    _error: *mut c_int,
    _pathname: *const c_char,
    _flags: c_int,
) -> c_int {
    0
}

#[no_mangle]
pub extern "C" fn u_mprotect_ocall(
    _error: *mut c_int,
    _addr: *mut c_void,
    _length: usize,
    _prot: c_int,
) -> c_int {
    0
}

#[no_mangle]
pub extern "C" fn u_msync_ocall(
    _error: *mut c_int,
    _addr: *mut c_void,
    _length: usize,
    _flags: c_int,
) -> c_int {
    0
}

#[no_mangle]
pub extern "C" fn u_munmap_ocall(_error: *mut c_int, _start: *mut c_void, _length: isize) -> c_int {
    0
}

#[no_mangle]
pub extern "C" fn u_mmap_ocall(
    _error: *mut c_int,
    _start: *mut c_void,
    _length: usize,
    _prot: c_int,
    _flags: c_int,
    _fd: c_int,
    _offset: i64,
) -> *mut c_void {
    core::ptr::null_mut()
}

#[no_mangle]
pub extern "C" fn u_free_ocall(_p: *mut c_void) {}

#[no_mangle]
pub extern "C" fn u_malloc_ocall(_error: *mut c_int, _size: usize) -> *mut c_void {
    core::ptr::null_mut()
}

#[no_mangle]
pub extern "C" fn u_futimens_ocall(_error: *mut c_int, _fd: c_int, _times: *const c_char) -> c_int {
    0
}

#[no_mangle]
pub extern "C" fn u_eventfd_ocall(_error: *mut c_int, _initval: c_uint, _flags: c_int) -> c_int {
    0
}

#[no_mangle]
pub extern "C" fn u_dup_ocall(_error: *mut c_int, _oldfd: c_int) -> c_int {
    0
}

#[no_mangle]
pub extern "C" fn u_isatty_ocall(_error: *mut c_int, _fd: c_int) -> c_int {
    0
}

#[no_mangle]
pub extern "C" fn u_close_ocall(_error: *mut c_int, _fd: c_int) -> c_int {
    0
}

#[no_mangle]
pub extern "C" fn u_ioctl_arg1_ocall(
    _error: *mut c_int,
    _fd: c_int,
    _request: c_int,
    _arg: *mut c_int,
) -> c_int {
    0
}

#[no_mangle]
pub extern "C" fn u_ioctl_arg0_ocall(_error: *mut c_int, _fd: c_int, _request: c_int) -> c_int {
    0
}

#[no_mangle]
pub extern "C" fn u_fcntl_arg1_ocall(
    _error: *mut c_int,
    _fd: c_int,
    _cmd: c_int,
    _arg: c_int,
) -> c_int {
    0
}

#[no_mangle]
pub extern "C" fn u_fcntl_arg0_ocall(_error: *mut c_int, _fd: c_int, _cmd: c_int) -> c_int {
    0
}

#[no_mangle]
pub extern "C" fn u_splice_ocall(
    _error: *mut c_int,
    _fd_in: c_int,
    _off_in: *mut c_char,
    _fd_out: c_int,
    _off_out: *mut c_char,
    _len: isize,
    _flags: c_uint,
) -> isize {
    0
}

#[no_mangle]
pub extern "C" fn u_copy_file_range_ocall(
    _error: *mut c_int,
    _fd_in: c_int,
    _off_in: *mut c_char,
    _fd_out: c_int,
    _off_out: *mut c_char,
    _len: isize,
    _flags: c_uint,
) -> isize {
    0
}

#[no_mangle]
pub extern "C" fn u_sendfile_ocall(
    _error: *mut c_int,
    _out_fd: c_int,
    _in_fd: c_int,
    _offset: *mut c_char,
    _count: isize,
) -> isize {
    0
}

#[no_mangle]
pub extern "C" fn u_pwritev64_ocall(
    _error: *mut c_int,
    _fd: c_int,
    _iov: *const c_char,
    _iovcnt: c_int,
    _offset: i64,
) -> isize {
    0
}

#[no_mangle]
pub extern "C" fn u_writev_ocall(
    _error: *mut c_int,
    _fd: c_int,
    _iov: *const c_char,
    _iovcnt: c_int,
) -> isize {
    0
}

#[no_mangle]
pub extern "C" fn u_pwrite64_ocall(
    _error: *mut c_int,
    _fd: c_int,
    _buf: *const c_void,
    _count: isize,
    _offset: i64,
) -> isize {
    0
}

#[no_mangle]
pub extern "C" fn u_write_ocall(
    _error: *mut c_int,
    _fd: c_int,
    _buf: *const c_void,
    _count: isize,
) -> isize {
    0
}

#[no_mangle]
pub extern "C" fn u_preadv64_ocall(
    _error: *mut c_int,
    _fd: c_int,
    _iov: *const c_char,
    _iovcnt: c_int,
    _offset: i64,
) -> isize {
    0
}

#[no_mangle]
pub extern "C" fn u_readv_ocall(
    _error: *mut c_int,
    _fd: c_int,
    _iov: *const c_char,
    _iovcnt: c_int,
) -> isize {
    0
}

#[no_mangle]
pub extern "C" fn u_pread64_ocall(
    _error: *mut c_int,
    _fd: c_int,
    _buf: *mut c_void,
    _count: isize,
    _offset: i64,
) -> isize {
    0
}

#[no_mangle]
pub extern "C" fn u_read_ocall(
    _error: *mut c_int,
    _fd: c_int,
    _buf: *mut c_void,
    _count: isize,
) -> isize {
    0
}

#[no_mangle]
pub extern "C" fn u_thread_setwait_events_ocall(
    _error: *mut c_int,
    _waiter_tcs: *const c_void,
    _self_tcs: *const c_void,
    _timeout: *const c_char,
) -> c_int {
    0
}

#[no_mangle]
pub extern "C" fn u_thread_set_multiple_events_ocall(
    _error: *mut c_int,
    _tcss: *const *const c_void,
    _total: c_int,
) -> c_int {
    0
}

#[no_mangle]
pub extern "C" fn u_thread_wait_event_ocall(
    _error: *mut c_int,
    _tcs: *const c_void,
    _timeout: *const c_char,
) -> c_int {
    0
}

#[no_mangle]
pub extern "C" fn u_thread_set_event_ocall(_error: *mut c_int, _tcs: *const c_void) -> c_int {
    0
}

#[no_mangle]
pub extern "C" fn t_global_init_ecall(_id: u64, _path: *const u8, _len: usize) {}
