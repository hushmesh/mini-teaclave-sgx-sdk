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
