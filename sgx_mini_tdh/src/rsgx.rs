use core::mem;
use sgx_mini_types::marker::ContiguousMemory;
use sgx_mini_types::*;

pub(crate) fn rsgx_raw_is_within_enclave(addr: *const u8, size: usize) -> bool {
    let ret = unsafe { sgx_is_within_enclave(addr as *const c_void, size) };
    ret != 0
}

///
/// rsgx_data_is_within_enclave checks whether a given address is within enclave memory.
///
#[inline]
pub(crate) fn rsgx_data_is_within_enclave<T: Copy + ContiguousMemory>(data: &T) -> bool {
    rsgx_raw_is_within_enclave(data as *const _ as *const u8, mem::size_of::<T>())
}

///
/// rsgx_slice_is_within_enclave checks whether a given address is within enclave memory.
///
#[inline]
pub(crate) fn rsgx_slice_is_within_enclave<T: Copy + ContiguousMemory>(data: &[T]) -> bool {
    rsgx_raw_is_within_enclave(data.as_ptr() as *const u8, mem::size_of_val(data))
}

///
/// The rsgx_rijndael128_cmac_msg function performs a standard 128bit CMAC hash over the input data buffer.
///
/// # Description
///
/// The rsgx_rijndael128_cmac_msg function performs a standard CMAC hash over the input data buffer.
/// Only a 128-bit version of the CMAC hash is supported.
///
/// The function should be used if the complete input data stream is available.
/// Otherwise, the Init, Update… Update, Final procedure should be used to compute
/// a CMAC hash over multiple input data sets.
///
/// # Parameters
///
/// **key**
///
/// A pointer to key to be used in the CMAC hash operation. The size must be 128 bits.
///
/// **src**
///
/// A pointer to the input data stream to be hashed.
///
/// # Requirements
///
/// Library: libsgx_tcrypto.a
///
/// # Return value
///
/// The 128-bit hash that has been CMAC calculated
///
/// # Errors
///
/// **SGX_ERROR_INVALID_PARAMETER**
///
/// The pointer is invalid.
///
/// **SGX_ERROR_OUT_OF_MEMORY**
///
/// Not enough memory is available to complete this operation.
///
/// **SGX_ERROR_UNEXPECTED**
///
/// An internal cryptography library failure occurred.
///
pub(crate) fn rsgx_rijndael128_cmac_msg<T>(
    key: &sgx_cmac_128bit_key_t,
    src: &T,
) -> SgxResult<sgx_cmac_128bit_tag_t>
where
    T: Copy + ContiguousMemory,
{
    let size = mem::size_of::<T>();
    if size == 0 {
        return Err(sgx_status_t::SGX_ERROR_INVALID_PARAMETER);
    }
    if size > u32::MAX as usize {
        return Err(sgx_status_t::SGX_ERROR_INVALID_PARAMETER);
    }

    let mut mac = sgx_cmac_128bit_tag_t::default();
    let ret = unsafe {
        sgx_rijndael128_cmac_msg(
            key as *const sgx_cmac_128bit_key_t,
            src as *const _ as *const u8,
            size as u32,
            &mut mac as *mut sgx_cmac_128bit_tag_t,
        )
    };
    match ret {
        sgx_status_t::SGX_SUCCESS => Ok(mac),
        _ => Err(ret),
    }
}

pub(crate) fn rsgx_rijndael128_align_cmac_slice<T>(
    key: &sgx_cmac_128bit_key_t,
    src: &[T],
) -> SgxResult<sgx_align_mac_128bit_t>
where
    T: Copy + ContiguousMemory,
{
    let size = mem::size_of_val(src);
    if size == 0 {
        return Err(sgx_status_t::SGX_ERROR_INVALID_PARAMETER);
    }
    if size > u32::MAX as usize {
        return Err(sgx_status_t::SGX_ERROR_INVALID_PARAMETER);
    }

    let mut align_mac = sgx_align_mac_128bit_t::default();
    let ret = unsafe {
        sgx_rijndael128_cmac_msg(
            key as *const sgx_cmac_128bit_key_t,
            src.as_ptr() as *const u8,
            size as u32,
            &mut align_mac.mac as *mut sgx_cmac_128bit_tag_t,
        )
    };
    match ret {
        sgx_status_t::SGX_SUCCESS => Ok(align_mac),
        _ => Err(ret),
    }
}

pub(crate) fn rsgx_ecc256_open_context(ecc_handle: &mut sgx_ecc_state_handle_t) -> sgx_status_t {
    unsafe { sgx_ecc256_open_context(ecc_handle as *mut _ as *mut sgx_ecc_state_handle_t) }
}

pub(crate) fn rsgx_ecc256_close_context(ecc_handle: sgx_ecc_state_handle_t) -> sgx_status_t {
    unsafe { sgx_ecc256_close_context(ecc_handle) }
}

pub(crate) fn rsgx_ecc256_create_key_pair(
    private: &mut sgx_ec256_private_t,
    public: &mut sgx_ec256_public_t,
    ecc_handle: sgx_ecc_state_handle_t,
) -> sgx_status_t {
    unsafe {
        sgx_ecc256_create_key_pair(
            private as *mut sgx_ec256_private_t,
            public as *mut sgx_ec256_public_t,
            ecc_handle,
        )
    }
}

pub(crate) fn rsgx_ecc256_compute_shared_dhkey(
    private_b: &sgx_ec256_private_t,
    public_ga: &sgx_ec256_public_t,
    shared_key: &mut sgx_ec256_dh_shared_t,
    ecc_handle: sgx_ecc_state_handle_t,
) -> sgx_status_t {
    unsafe {
        sgx_ecc256_compute_shared_dhkey(
            private_b as *const sgx_ec256_private_t,
            public_ga as *const sgx_ec256_public_t,
            shared_key as *mut sgx_ec256_dh_shared_t,
            ecc_handle,
        )
    }
}

pub(crate) fn rsgx_cmac128_init(
    key: &sgx_cmac_128bit_key_t,
    cmac_handle: &mut sgx_cmac_state_handle_t,
) -> sgx_status_t {
    unsafe {
        sgx_cmac128_init(
            key as *const sgx_cmac_128bit_key_t,
            cmac_handle as *mut sgx_cmac_state_handle_t,
        )
    }
}

pub(crate) fn rsgx_cmac128_update_msg<T>(
    src: &T,
    cmac_handle: sgx_cmac_state_handle_t,
) -> sgx_status_t
where
    T: Copy + ContiguousMemory,
{
    let size = mem::size_of::<T>();
    if size == 0 {
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    }
    if size > u32::MAX as usize {
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    }
    unsafe { sgx_cmac128_update(src as *const _ as *const u8, size as u32, cmac_handle) }
}

pub(crate) fn rsgx_cmac128_update_slice<T>(
    src: &[T],
    cmac_handle: sgx_cmac_state_handle_t,
) -> sgx_status_t
where
    T: Copy + ContiguousMemory,
{
    let size = mem::size_of_val(src);
    if size == 0 {
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    }
    if size > u32::MAX as usize {
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    }
    unsafe {
        sgx_cmac128_update(
            src.as_ptr() as *const _ as *const u8,
            size as u32,
            cmac_handle,
        )
    }
}

pub(crate) fn rsgx_cmac128_final(
    cmac_handle: sgx_cmac_state_handle_t,
    hash: &mut sgx_cmac_128bit_tag_t,
) -> sgx_status_t {
    unsafe { sgx_cmac128_final(cmac_handle, hash as *mut sgx_cmac_128bit_tag_t) }
}

pub(crate) fn rsgx_cmac128_close(cmac_handle: sgx_cmac_state_handle_t) -> sgx_status_t {
    unsafe { sgx_cmac128_close(cmac_handle) }
}

pub(crate) fn rsgx_sha256_init(sha_handle: &mut sgx_sha_state_handle_t) -> sgx_status_t {
    unsafe { sgx_sha256_init(sha_handle as *mut sgx_sha_state_handle_t) }
}

pub(crate) fn rsgx_sha256_update_msg<T>(src: &T, sha_handle: sgx_sha_state_handle_t) -> sgx_status_t
where
    T: Copy + ContiguousMemory,
{
    let size = mem::size_of::<T>();
    if size == 0 {
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    }
    if size > u32::MAX as usize {
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    }

    unsafe { sgx_sha256_update(src as *const _ as *const u8, size as u32, sha_handle) }
}

pub(crate) fn rsgx_sha256_get_hash(
    sha_handle: sgx_sha_state_handle_t,
    hash: &mut sgx_sha256_hash_t,
) -> sgx_status_t {
    unsafe { sgx_sha256_get_hash(sha_handle, hash as *mut sgx_sha256_hash_t) }
}

pub(crate) fn rsgx_sha256_close(sha_handle: sgx_sha_state_handle_t) -> sgx_status_t {
    unsafe { sgx_sha256_close(sha_handle) }
}

///
/// The rsgx_create_report function tries to use the information of the target enclave and other information
/// to create a cryptographic report of the enclave.
///
/// This function is a wrapper for the SGX EREPORT instruction.
///
/// # Description
///
/// Use the function rsgx_create_report to create a cryptographic report that describes the contents of the
/// calling enclave. The report can be used by other enclaves to verify that the enclave is running on the
/// same platform. When an enclave calls rsgx_verify_report to verify a report, it will succeed only if
/// the report was generated using the target_info for said enclave. This function is a wrapper for the SGX EREPORT
/// instruction.
///
/// Before the source enclave calls rsgx_create_report to generate a report, it needs to populate target_info with
/// information about the target enclave that will verify the report. The target enclave may obtain this information
/// calling rsgx_create_report with a default value for target_info and pass it to the source enclave at the beginning
/// of the inter-enclave attestation process.
///
/// # Parameters
///
/// **target_info**
///
/// A pointer to the sgx_target_info_t object that contains the information of the target enclave,
/// which will be able to cryptographically verify the report calling rsgx_verify_report.efore calling this function.
///
/// If value is default, sgx_create_report retrieves information about the calling enclave,
/// but the generated report cannot be verified by any enclave.
///
/// **report_data**
///
/// A pointer to the sgx_report_data_t object which contains a set of data used for communication between the enclaves.
///
/// # Requirements
///
/// Library: libsgx_tservice.a
///
/// # Return value
///
/// Cryptographic report of the enclave
///
/// # Errors
///
/// **SGX_ERROR_INVALID_PARAMETER**
///
/// An error is reported if any of the parameters memory is not within the enclave or the reserved fields
/// of the data structure are not set to zero.
///
/// **SGX_ERROR_OUT_OF_MEMORY**
///
/// Indicates that the enclave is out of memory.
///
pub(crate) fn rsgx_create_report(
    target_info: &sgx_target_info_t,
    report_data: &sgx_report_data_t,
) -> SgxResult<sgx_report_t> {
    let mut report = sgx_report_t::default();
    let ret = unsafe {
        sgx_create_report(
            target_info as *const sgx_target_info_t,
            report_data as *const sgx_report_data_t,
            &mut report as *mut sgx_report_t,
        )
    };
    match ret {
        sgx_status_t::SGX_SUCCESS => Ok(report),
        _ => Err(ret),
    }
}

///
/// The rsgx_verify_report function provides software verification for the report which is expected to be
/// generated by the rsgx_create_report function.
///
/// # Description
///
/// The rsgx_verify_report performs a cryptographic CMAC function of the input sgx_report_data_t object
/// in the report using the report key. Then the function compares the input report MAC value with the
/// calculated MAC value to determine whether the report is valid or not.
///
/// # Parameters
///
/// **report**
///
/// A pointer to an sgx_report_t object that contains the cryptographic report to be verified.
/// The report buffer must be within the enclave.
///
/// # Requirements
///
/// Library: libsgx_tservice.a
///
/// # Errors
///
/// **SGX_ERROR_INVALID_PARAMETER**
///
/// The report object is invalid.
///
/// **SGX_ERROR_MAC_MISMATCH**
///
/// Indicates report verification error.
///
/// **SGX_ERROR_UNEXPECTED**
///
/// Indicates an unexpected error occurs during the report verification process.
///
pub(crate) fn rsgx_verify_report(report: &sgx_report_t) -> SgxError {
    let ret = unsafe { sgx_verify_report(report as *const sgx_report_t) };
    match ret {
        sgx_status_t::SGX_SUCCESS => Ok(()),
        _ => Err(ret),
    }
}

pub(crate) fn rsgx_self_report() -> sgx_report_t {
    unsafe { *sgx_self_report() }
}

#[inline(always)]
pub(crate) fn rsgx_lfence() {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        asm! {"lfence"};
    }
}
