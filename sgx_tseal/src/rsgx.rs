#[cfg(target_arch = "x86_64")]
use core::arch::asm;
use core::mem;
use core::ptr;
use sgx_types::marker::*;
use sgx_types::*;

pub(crate) fn rsgx_raw_is_within_enclave(addr: *const u8, size: usize) -> bool {
    let ret = unsafe { sgx_is_within_enclave(addr as *const c_void, size) };
    ret != 0
}

pub(crate) fn rsgx_raw_is_outside_enclave(addr: *const u8, size: usize) -> bool {
    let ret = unsafe { sgx_is_outside_enclave(addr as *const c_void, size) };
    ret != 0
}

#[inline]
pub(crate) fn rsgx_slice_is_within_enclave<T: Copy + ContiguousMemory>(data: &[T]) -> bool {
    rsgx_raw_is_within_enclave(data.as_ptr() as *const u8, mem::size_of_val(data))
}

#[inline]
pub(crate) fn rsgx_slice_is_outside_enclave<T: Copy + ContiguousMemory>(data: &[T]) -> bool {
    rsgx_raw_is_outside_enclave(data.as_ptr() as *const u8, mem::size_of_val(data))
}

pub(crate) fn rsgx_self_report() -> sgx_report_t {
    unsafe { *sgx_self_report() }
}

pub(crate) fn rsgx_get_align_key(
    key_request: &sgx_key_request_t,
) -> SgxResult<sgx_align_key_128bit_t> {
    let mut align_key = sgx_align_key_128bit_t::default();
    let ret = unsafe {
        sgx_get_key(
            key_request as *const sgx_key_request_t,
            &mut align_key.key as *mut sgx_key_128bit_t,
        )
    };
    match ret {
        sgx_status_t::SGX_SUCCESS => Ok(align_key),
        _ => Err(ret),
    }
}

#[inline(always)]
pub(crate) fn rsgx_lfence() {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        asm! {"lfence"};
    }
}

///
/// rsgx_rijndael128GCM_encrypt performs a Rijndael AES-GCM encryption operation.
///
/// Only a 128bit key size is supported by this Intel(R) SGX SDK cryptography library.
///
/// # Description
///
/// The Galois/Counter Mode (GCM) is a mode of operation of the AES algorithm.
/// GCM [NIST SP 800-38D] uses a variation of the counter mode of operation for
/// encryption. GCM assures authenticity of the confidential data (of up to about
/// 64 GB per invocation) using a universal hash function defined over a binary
/// finite field (the Galois field).
///
/// GCM can also provide authentication assurance for additional data (of practically
/// unlimited length per invocation) that is not encrypted. GCM provides
/// stronger authentication assurance than a (non-cryptographic) checksum or
/// error detecting code. In particular, GCM can detect both accidental modifications
/// of the data and intentional, unauthorized modifications.
///
/// It is recommended that the source and destination data buffers are allocated
/// within the enclave. The AAD buffer could be allocated within or outside
/// enclave memory. The use of AAD data buffer could be information identifying
/// the encrypted data since it will remain in clear text.
///
/// # Parameters
///
/// **key**
///
/// A pointer to key to be used in the AES-GCM encryption operation. The size must be 128 bits.
///
/// **src**
///
/// A pointer to the input data stream to be encrypted. Buffer content could be empty if there is AAD text.
///
/// **iv**
///
/// A pointer to the initialization vector to be used in the AES-GCM calculation. NIST AES-GCM recommended
/// IV size is 96 bits (12 bytes).
///
/// **aad**
///
/// A pointer to an optional additional authentication data buffer which is used in the GCM MAC calculation.
/// The data in this buffer will not be encrypted. The field is optional and content could be empty.
///
/// **dst**
///
/// A pointer to the output encrypted data buffer. This buffer should be allocated by the calling code.
///
/// **mac**
///
/// This is the output GCM MAC performed over the input data buffer (data to be encrypted) as well as
/// the additional authentication data (this is optional data). The calling code should allocate this buffer.
///
/// # Requirements
///
/// Library: libsgx_tcrypto.a
///
/// # Errors
///
/// **SGX_ERROR_INVALID_PARAMETER**
///
/// If both source buffer and AAD buffer content are empty.
///
/// If IV Length is not equal to 12 (bytes).
///
/// **SGX_ERROR_OUT_OF_MEMORY**
///
/// Not enough memory is available to complete this operation.
///
/// **SGX_ERROR_UNEXPECTED**
///
/// An internal cryptography library failure occurred.
///
pub(crate) fn rsgx_rijndael128GCM_encrypt(
    key: &sgx_aes_gcm_128bit_key_t,
    src: &[u8],
    iv: &[u8],
    aad: &[u8],
    dst: &mut [u8],
    mac: &mut sgx_aes_gcm_128bit_tag_t,
) -> SgxError {
    let src_len = src.len();
    if src_len > u32::MAX as usize {
        return Err(sgx_status_t::SGX_ERROR_INVALID_PARAMETER);
    }
    let iv_len = iv.len();
    if iv_len != SGX_AESGCM_IV_SIZE {
        return Err(sgx_status_t::SGX_ERROR_INVALID_PARAMETER);
    }
    let aad_len = aad.len();
    if aad_len > u32::MAX as usize {
        return Err(sgx_status_t::SGX_ERROR_INVALID_PARAMETER);
    }
    let dst_len = dst.len();
    if dst_len > u32::MAX as usize {
        return Err(sgx_status_t::SGX_ERROR_INVALID_PARAMETER);
    }
    if dst_len < src_len {
        return Err(sgx_status_t::SGX_ERROR_INVALID_PARAMETER);
    }

    let ret = unsafe {
        let p_aad = if aad_len != 0 {
            aad.as_ptr()
        } else {
            ptr::null()
        };

        let (p_src, p_dst) = if src_len != 0 {
            (src.as_ptr(), dst.as_mut_ptr())
        } else {
            (ptr::null(), ptr::null_mut())
        };

        sgx_rijndael128GCM_encrypt(
            key as *const sgx_aes_gcm_128bit_key_t,
            p_src,
            src_len as u32,
            p_dst,
            iv.as_ptr(),
            iv_len as u32,
            p_aad,
            aad_len as u32,
            mac as *mut sgx_aes_gcm_128bit_tag_t,
        )
    };
    match ret {
        sgx_status_t::SGX_SUCCESS => Ok(()),
        _ => Err(ret),
    }
}

///
/// rsgx_rijndael128GCM_decrypt performs a Rijndael AES-GCM decryption operation.
///
/// Only a 128bit key size is supported by this Intel(R) SGX SDK cryptography library.
///
/// # Description
///
/// The Galois/Counter Mode (GCM) is a mode of operation of the AES algorithm.
/// GCM [NIST SP 800-38D] uses a variation of the counter mode of operation for
/// encryption. GCM assures authenticity of the confidential data (of up to about
/// 64 GB per invocation) using a universal hash function defined over a binary
/// finite field (the Galois field).
///
/// GCM can also provide authentication assurance for additional data (of practically
/// unlimited length per invocation) that is not encrypted. GCM provides
/// stronger authentication assurance than a (non-cryptographic) checksum or
/// error detecting code. In particular, GCM can detect both accidental modifications
/// of the data and intentional, unauthorized modifications.
///
/// It is recommended that the destination data buffer is allocated within the
/// enclave. The AAD buffer could be allocated within or outside enclave memory.
///
/// # Parameters
///
/// **key**
///
/// A pointer to key to be used in the AES-GCM decryption operation. The size must be 128 bits.
///
/// **src**
///
/// A pointer to the input data stream to be decrypted. Buffer content could be empty if there is AAD text.
///
/// **iv**
///
/// A pointer to the initialization vector to be used in the AES-GCM calculation. NIST AES-GCM recommended
/// IV size is 96 bits (12 bytes).
///
/// **aad**
///
/// A pointer to an optional additional authentication data buffer which is provided for the GCM MAC calculation
/// when encrypting. The data in this buffer was not encrypted. The field is optional and content could be empty.
///
/// **mac**
///
/// This is the GCM MAC that was performed over the input data buffer (data to be encrypted) as well as
/// the additional authentication data (this is optional data) during the encryption process (call to
/// rsgx_rijndael128GCM_encrypt).
///
/// **dst**
///
/// A pointer to the output decrypted data buffer. This buffer should be allocated by the calling code.
///
/// # Requirements
///
/// Library: libsgx_tcrypto.a
///
/// # Errors
///
/// **SGX_ERROR_INVALID_PARAMETER**
///
/// If both source buffer and AAD buffer content are empty.
///
/// If IV Length is not equal to 12 (bytes).
///
/// **SGX_ERROR_MAC_MISMATCH**
///
/// The input MAC does not match the MAC calculated.
///
/// **SGX_ERROR_OUT_OF_MEMORY**
///
/// Not enough memory is available to complete this operation.
///
/// **SGX_ERROR_UNEXPECTED**
///
/// An internal cryptography library failure occurred.
///
pub(crate) fn rsgx_rijndael128GCM_decrypt(
    key: &sgx_aes_gcm_128bit_key_t,
    src: &[u8],
    iv: &[u8],
    aad: &[u8],
    mac: &sgx_aes_gcm_128bit_tag_t,
    dst: &mut [u8],
) -> SgxError {
    let src_len = src.len();
    if src_len > u32::MAX as usize {
        return Err(sgx_status_t::SGX_ERROR_INVALID_PARAMETER);
    }
    let iv_len = iv.len();
    if iv_len != SGX_AESGCM_IV_SIZE {
        return Err(sgx_status_t::SGX_ERROR_INVALID_PARAMETER);
    }
    let aad_len = aad.len();
    if aad_len > u32::MAX as usize {
        return Err(sgx_status_t::SGX_ERROR_INVALID_PARAMETER);
    }
    let dst_len = dst.len();
    if dst_len > u32::MAX as usize {
        return Err(sgx_status_t::SGX_ERROR_INVALID_PARAMETER);
    }
    if dst_len < src_len {
        return Err(sgx_status_t::SGX_ERROR_INVALID_PARAMETER);
    }

    let ret = unsafe {
        let p_aad = if !aad.is_empty() {
            aad.as_ptr()
        } else {
            ptr::null()
        };

        let (p_src, p_dst) = if src_len != 0 {
            (src.as_ptr(), dst.as_mut_ptr())
        } else {
            (ptr::null(), ptr::null_mut())
        };

        sgx_rijndael128GCM_decrypt(
            key as *const sgx_aes_gcm_128bit_key_t,
            p_src,
            src_len as u32,
            p_dst,
            iv.as_ptr(),
            iv_len as u32,
            p_aad,
            aad_len as u32,
            mac as *const sgx_aes_gcm_128bit_tag_t,
        )
    };
    match ret {
        sgx_status_t::SGX_SUCCESS => Ok(()),
        _ => Err(ret),
    }
}

///
/// rsgx_read_rand function is used to generate a random number inside the enclave.
///
/// # Description
///
/// The rsgx_read_rand function is provided to replace the standard pseudo-random sequence generation functions
/// inside the enclave, since these standard functions are not supported in the enclave, such as rand, srand, etc.
/// For HW mode, the function generates a real-random sequence; while in simulation mode, the function generates
/// a pseudo-random sequence.
///
/// # Parameters
///
/// **rand**
///
/// A pointer to the buffer that stores the generated random number. The rand buffer can be either within or outside the enclave,
/// but it is not allowed to be across the enclave boundary or wrapped around.
///
/// # Requirements
///
/// Library: libsgx_trts.a
///
/// # Errors
///
/// **SGX_ERROR_INVALID_PARAMETER**
///
/// Invalid input parameters detected.
///
/// **SGX_ERROR_UNEXPECTED**
///
/// Indicates an unexpected error occurs during the valid random number generation process.
///
pub(crate) fn rsgx_read_rand(rand: &mut [u8]) -> SgxError {
    let ret = unsafe { sgx_read_rand(rand.as_mut_ptr(), rand.len()) };
    match ret {
        sgx_status_t::SGX_SUCCESS => Ok(()),
        _ => Err(ret),
    }
}
