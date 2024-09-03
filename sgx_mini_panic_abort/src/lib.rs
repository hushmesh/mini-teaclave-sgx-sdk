#![no_std]
#![cfg(not(test))]

use core::panic::PanicInfo;

use log::error;

#[link(name = "sgx_trts")]
extern "C" {
    pub fn abort() -> !;
}

pub fn panic_handler(info: &PanicInfo) -> ! {
    error!("Panic: {}", info);
    log::logger().flush();
    unsafe {
        abort();
    }
}
