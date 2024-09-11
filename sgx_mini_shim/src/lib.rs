#![no_std]

use core::ffi::c_char;
use core::ffi::c_int;
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
