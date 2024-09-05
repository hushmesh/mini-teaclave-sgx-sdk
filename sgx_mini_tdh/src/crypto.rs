use core::cell::Cell;
use core::cell::RefCell;
use core::ops::DerefMut;
use core::ptr;

use crate::rsgx::*;
use sgx_mini_types::marker::ContiguousMemory;
use sgx_mini_types::*;

///
/// ECC GF(p) context state.
///
/// This is a handle to the ECC GF(p) context state allocated and initialized used to perform
/// elliptic curve cryptosystem standard functions. The algorithm stores the intermediate results
/// of calculations performed using this context.
///
pub struct SgxEccHandle {
    handle: RefCell<sgx_ecc_state_handle_t>,
    initflag: Cell<bool>,
}

impl SgxEccHandle {
    ///
    /// Constructs a new, empty SgxEccHandle.
    ///
    pub fn new() -> SgxEccHandle {
        SgxEccHandle {
            handle: RefCell::new(ptr::null_mut() as sgx_ecc_state_handle_t),
            initflag: Cell::new(false),
        }
    }

    ///
    /// open returns an allocated and initialized context for the elliptic curve cryptosystem
    /// over a prime finite field, GF(p).
    ///
    /// This context must be created prior to calling create_key_pair or compute_shared_dhkey.
    /// When the calling code has completed its set of ECC operations, close should be called to
    /// cleanup and deallocate the ECC context.
    ///
    /// # Description
    ///
    /// open is utilized to allocate and initialize a 256-bit
    /// GF(p) cryptographic system. The caller does not allocate memory for the ECC
    /// state that this function returns. The state is specific to the implementation of
    /// the cryptography library and thus the allocation is performed by the library
    /// itself. If the ECC cryptographic function using this cryptographic system is completed
    /// or any error occurs, close should be called to free the state allocated by this algorithm.
    ///
    /// Public key cryptography successfully allows to solving problems of information
    /// safety by enabling trusted communication over insecure channels. Although
    /// elliptic curves are well studied as a branch of mathematics, an interest to the
    /// cryptographic schemes based on elliptic curves is constantly rising due to the
    /// advantages that the elliptic curve algorithms provide in the wireless communications:
    /// shorter processing time and key length.
    ///
    /// Elliptic curve cryptosystems (ECCs) implement a different way of creating public
    /// keys. As elliptic curve calculation is based on the addition of the rational
    /// points in the (x,y) plane and it is difficult to solve a discrete logarithm from
    /// these points, a higher level of safety is achieved through the cryptographic
    /// schemes that use the elliptic curves. The cryptographic systems that encrypt
    /// messages by using the properties of elliptic curves are hard to attack due to
    /// the extreme complexity of deciphering the private key.
    ///
    /// Using of elliptic curves allows shorter public key length and encourages cryptographers
    /// to create cryptosystems with the same or higher encryption
    /// strength as the RSA or DSA cryptosystems. Because of the relatively short key
    /// length, ECCs do encryption and decryption faster on the hardware that
    /// requires less computation processing volumes.
    ///
    /// # Requirements
    ///
    /// Library: libsgx_tcrypto.a
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
    /// The ECC context state was not initialized properly due to an internal cryptography library failure.
    ///
    pub fn open(&self) -> SgxError {
        if self.initflag.get() {
            return Ok(());
        }

        let ret = rsgx_ecc256_open_context(self.handle.borrow_mut().deref_mut());
        match ret {
            sgx_status_t::SGX_SUCCESS => {
                self.initflag.set(true);
                Ok(())
            }
            _ => Err(ret),
        }
    }

    pub fn create_align_key_pair(
        &self,
    ) -> SgxResult<(sgx_align_ec256_private_t, sgx_ec256_public_t)> {
        if !self.initflag.get() {
            return Err(sgx_status_t::SGX_ERROR_INVALID_STATE);
        }

        let mut private = sgx_align_ec256_private_t::default();
        let mut public = sgx_ec256_public_t::default();
        let ret = rsgx_ecc256_create_key_pair(&mut private.key, &mut public, *self.handle.borrow());

        match ret {
            sgx_status_t::SGX_SUCCESS => Ok((private, public)),
            _ => Err(ret),
        }
    }

    pub fn compute_align_shared_dhkey(
        &self,
        private_b: &sgx_ec256_private_t,
        public_ga: &sgx_ec256_public_t,
    ) -> SgxResult<sgx_align_ec256_dh_shared_t> {
        if !self.initflag.get() {
            return Err(sgx_status_t::SGX_ERROR_INVALID_STATE);
        }

        let mut shared_key = sgx_align_ec256_dh_shared_t::default();
        let ret = rsgx_ecc256_compute_shared_dhkey(
            private_b,
            public_ga,
            &mut shared_key.key,
            *self.handle.borrow(),
        );
        match ret {
            sgx_status_t::SGX_SUCCESS => Ok(shared_key),
            _ => Err(ret),
        }
    }

    ///
    /// close cleans up and deallocates the ECC 256 GF(p) state that was allocated in function open.
    ///
    /// # Description
    ///
    /// close is used by calling code to deallocate memory used for storing the ECC 256 GF(p) state used
    /// in ECC cryptographic calculations.
    ///
    /// # Requirements
    ///
    /// Library: libsgx_tcrypto.a
    ///
    /// # Errors
    ///
    /// **SGX_ERROR_INVALID_PARAMETER**
    ///
    /// The input handle is invalid.
    ///
    pub fn close(&self) -> SgxError {
        if !self.initflag.get() {
            return Ok(());
        }

        let ret = {
            let handle = *self.handle.borrow();
            if handle.is_null() {
                sgx_status_t::SGX_SUCCESS
            } else {
                rsgx_ecc256_close_context(handle)
            }
        };

        match ret {
            sgx_status_t::SGX_SUCCESS => {
                self.initflag.set(false);
                *self.handle.borrow_mut() = ptr::null_mut();
                Ok(())
            }
            _ => Err(ret),
        }
    }
}

impl Default for SgxEccHandle {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for SgxEccHandle {
    ///
    /// close cleans up and deallocates the ECC 256 GF(p) state that was allocated in function open.
    ///
    fn drop(&mut self) {
        let _ = self.close();
    }
}

///
/// CMAC algorithm context state.
///
/// This is a handle to the context state used by the cryptography library to perform an
/// iterative CMAC 128-bit hash. The algorithm stores the intermediate results of performing
/// the hash calculation over data sets.
///
pub struct SgxCmacHandle {
    handle: RefCell<sgx_cmac_state_handle_t>,
    initflag: Cell<bool>,
}

impl SgxCmacHandle {
    ///
    /// Constructs a new, empty SgxCmacHandle.
    ///
    pub fn new() -> SgxCmacHandle {
        SgxCmacHandle {
            handle: RefCell::new(ptr::null_mut() as sgx_cmac_state_handle_t),
            initflag: Cell::new(false),
        }
    }

    ///
    /// init returns an allocated and initialized CMAC algorithm context state.
    ///
    /// This should be part of the Init, Update … Update, Final process when the CMAC hash is to be
    /// performed over multiple datasets. If a complete dataset is available, the recommended call
    /// is rsgx_rijndael128_cmac_msg to perform the hash in a single call.
    ///
    /// # Description
    ///
    /// Calling init is the first set in performing a CMAC 128-bit hash over multiple datasets.
    /// The caller does not allocate memory for the CMAC state that this function returns.
    /// The state is specific to the implementation of the cryptography library and thus the
    /// allocation is performed by the library itself. If the hash over the desired datasets is
    /// completed or any error occurs during the hash calculation process, sgx_cmac128_close should
    /// be called to free the state allocated by this algorithm.
    ///
    /// # Parameters
    ///
    /// **key**
    ///
    /// A pointer to key to be used in the CMAC hash operation. The size must be 128 bits.
    ///
    /// # Requirements
    ///
    /// Library: libsgx_tcrypto.a
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
    pub fn init(&self, key: &sgx_cmac_128bit_key_t) -> SgxError {
        if self.initflag.get() {
            return Ok(());
        }

        let ret = rsgx_cmac128_init(key, self.handle.borrow_mut().deref_mut());
        match ret {
            sgx_status_t::SGX_SUCCESS => {
                self.initflag.set(true);
                Ok(())
            }
            _ => Err(ret),
        }
    }

    ///
    /// update_msg performs a CMAC 128-bit hash over the input dataset provided.
    ///
    /// This function supports an iterative calculation of the hash over multiple datasets where the
    /// cmac_handle contains the intermediate results of the hash calculation over previous datasets.
    ///
    /// # Description
    ///
    /// This function should be used as part of a CMAC 128-bit hash calculation over
    /// multiple datasets. If a CMAC hash is needed over a single data set, function
    /// rsgx_rijndael128_cmac128_msg should be used instead. Prior to calling
    /// this function on the first dataset, the init function must be called first to
    /// allocate and initialize the CMAC state structure which will hold intermediate
    /// hash results over earlier datasets. The function get_hash should be used
    /// to obtain the hash after the final dataset has been processed by this function.
    ///
    /// # Parameters
    ///
    /// **src**
    ///
    /// A pointer to the input data stream to be hashed.
    ///
    /// # Requirements
    ///
    /// Library: libsgx_tcrypto.a
    ///
    /// # Errors
    ///
    /// **SGX_ERROR_INVALID_PARAMETER**
    ///
    /// The pointer is invalid.
    ///
    /// **SGX_ERROR_INVALID_STATE**
    ///
    /// The CMAC state is not initialized.
    ///
    /// **SGX_ERROR_OUT_OF_MEMORY**
    ///
    /// Not enough memory is available to complete this operation.
    ///
    /// **SGX_ERROR_UNEXPECTED**
    ///
    /// An internal cryptography library failure occurred while performing the CMAC hash calculation.
    ///
    pub fn update_msg<T>(&self, src: &T) -> SgxError
    where
        T: Copy + ContiguousMemory,
    {
        if !self.initflag.get() {
            return Err(sgx_status_t::SGX_ERROR_INVALID_STATE);
        }

        let ret = rsgx_cmac128_update_msg(src, *self.handle.borrow());
        match ret {
            sgx_status_t::SGX_SUCCESS => Ok(()),
            _ => Err(ret),
        }
    }

    ///
    /// update_slice performs a CMAC 128-bit hash over the input dataset provided.
    ///
    pub fn update_slice<T>(&self, src: &[T]) -> SgxError
    where
        T: Copy + ContiguousMemory,
    {
        if !self.initflag.get() {
            return Err(sgx_status_t::SGX_ERROR_INVALID_STATE);
        }

        let ret = rsgx_cmac128_update_slice(src, *self.handle.borrow());
        match ret {
            sgx_status_t::SGX_SUCCESS => Ok(()),
            _ => Err(ret),
        }
    }

    ///
    /// get_hash obtains the CMAC 128-bit hash after the final dataset has been processed.
    ///
    /// # Description
    ///
    /// This function returns the hash after performing the CMAC 128-bit hash calculation
    /// over one or more datasets using the update function.
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
    /// **SGX_ERROR_INVALID_STATE**
    ///
    /// The CMAC state is not initialized.
    ///
    /// **SGX_ERROR_UNEXPECTED**
    ///
    /// The CMAC state passed in is likely problematic causing an internal cryptography library failure.
    ///
    pub fn get_hash(&self) -> SgxResult<sgx_cmac_128bit_tag_t> {
        if !self.initflag.get() {
            return Err(sgx_status_t::SGX_ERROR_INVALID_STATE);
        }

        let mut hash = sgx_cmac_128bit_tag_t::default();
        let ret = rsgx_cmac128_final(*self.handle.borrow(), &mut hash);
        match ret {
            sgx_status_t::SGX_SUCCESS => Ok(hash),
            _ => Err(ret),
        }
    }
    ///
    /// close cleans up and deallocates the CMAC algorithm context state that was allocated in function init.
    ///
    /// # Description
    ///
    /// Calling close is the last step after performing a CMAC hash over multiple datasets.
    /// The caller uses this function to deallocate memory used for storing the CMAC algorithm context state.
    ///
    /// # Requirements
    ///
    /// Library: libsgx_tcrypto.a
    ///
    /// # Errors
    ///
    /// **SGX_ERROR_INVALID_PARAMETER**
    ///
    /// The input handle is invalid.
    ///
    pub fn close(&self) -> SgxError {
        if !self.initflag.get() {
            return Ok(());
        }

        let ret = {
            let handle = *self.handle.borrow();
            if handle.is_null() {
                sgx_status_t::SGX_SUCCESS
            } else {
                rsgx_cmac128_close(handle)
            }
        };

        match ret {
            sgx_status_t::SGX_SUCCESS => {
                self.initflag.set(false);
                *self.handle.borrow_mut() = ptr::null_mut();
                Ok(())
            }
            _ => Err(ret),
        }
    }
}

impl Default for SgxCmacHandle {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for SgxCmacHandle {
    ///
    /// drop cleans up and deallocates the CMAC algorithm context state that was allocated in function init.
    ///
    fn drop(&mut self) {
        let _ = self.close();
    }
}

///
/// SHA256 algorithm context state.
///
/// This is a handle to the context state used by the cryptography library to perform an iterative SHA256 hash.
/// The algorithm stores the intermediate results of performing the hash calculation over data sets.
///
pub struct SgxShaHandle {
    handle: RefCell<sgx_sha_state_handle_t>,
    initflag: Cell<bool>,
}

impl SgxShaHandle {
    ///
    /// Constructs a new, empty SgxShaHandle.
    ///
    pub fn new() -> SgxShaHandle {
        SgxShaHandle {
            handle: RefCell::new(ptr::null_mut() as sgx_sha_state_handle_t),
            initflag: Cell::new(false),
        }
    }

    ///
    /// init returns an allocated and initialized SHA algorithm context state.
    ///
    /// This should be part of the Init, Update … Update, Final process when the SHA hash is to be performed
    /// over multiple datasets. If a complete dataset is available, the recommend call is rsgx_sha256_msg to
    /// perform the hash in a single call.
    ///
    /// # Description
    ///
    /// Calling init is the first set in performing a SHA256 hash over multiple datasets. The caller does not
    /// allocate memory for the SHA256 state that this function returns. The state is specific to the implementation
    /// of the cryptography library; thus the allocation is performed by the library itself. If the hash over the
    /// desired datasets is completed or any error occurs during the hash calculation process, sgx_sha256_close should
    /// be called to free the state allocated by this algorithm.
    ///
    /// # Requirements
    ///
    /// Library: libsgx_tcrypto.a
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
    /// The SHA256 state is not initialized properly due to an internal cryptography library failure.
    ///
    pub fn init(&self) -> SgxError {
        if self.initflag.get() {
            return Ok(());
        }

        let ret = rsgx_sha256_init(self.handle.borrow_mut().deref_mut());
        match ret {
            sgx_status_t::SGX_SUCCESS => {
                self.initflag.set(true);
                Ok(())
            }
            _ => Err(ret),
        }
    }

    ///
    /// update_msg performs a SHA256 hash over the input dataset provided.
    ///
    /// This function supports an iterative calculation of the hash over multiple datasets where the
    /// sha_handle contains the intermediate results of the hash calculation over previous datasets.
    ///
    /// # Description
    ///
    /// This function should be used as part of a SHA256 calculation over multiple datasets.
    /// If a SHA256 hash is needed over a single data set, function rsgx_sha256_msg should be used instead.
    /// Prior to calling this function on the first dataset, the init function must be called first to allocate
    /// and initialize the SHA256 state structure which will hold intermediate hash results over earlier datasets.
    /// The function get_hash should be used to obtain the hash after the final dataset has been processed
    /// by this function.
    ///
    /// # Parameters
    ///
    /// **src**
    ///
    /// A pointer to the input data stream to be hashed.
    ///
    /// # Requirements
    ///
    /// Library: libsgx_tcrypto.a
    ///
    /// # Errors
    ///
    /// **SGX_ERROR_INVALID_PARAMETER**
    ///
    /// The pointer is invalid.
    ///
    /// **SGX_ERROR_INVALID_STATE**
    ///
    /// The SHA256 state is not initialized.
    ///
    /// **SGX_ERROR_UNEXPECTED**
    ///
    /// An internal cryptography library failure occurred while performing the SHA256 hash calculation.
    ///
    pub fn update_msg<T>(&self, src: &T) -> SgxError
    where
        T: Copy + ContiguousMemory,
    {
        if !self.initflag.get() {
            return Err(sgx_status_t::SGX_ERROR_INVALID_STATE);
        }

        let ret = rsgx_sha256_update_msg(src, *self.handle.borrow());
        match ret {
            sgx_status_t::SGX_SUCCESS => Ok(()),
            _ => Err(ret),
        }
    }

    ///
    /// update_slice performs a SHA256 hash over the input dataset provided.
    ///
    pub fn update_slice<T>(&self, src: &[T]) -> SgxError
    where
        T: Copy + ContiguousMemory,
    {
        if !self.initflag.get() {
            return Err(sgx_status_t::SGX_ERROR_INVALID_STATE);
        }

        let ret = rsgx_sha256_update_slice(src, *self.handle.borrow());
        match ret {
            sgx_status_t::SGX_SUCCESS => Ok(()),
            _ => Err(ret),
        }
    }

    ///
    /// get_hash obtains the SHA256 hash after the final dataset has been processed.
    ///
    /// # Description
    ///
    /// This function returns the hash after performing the SHA256 calculation over one or more datasets
    /// using the update function.
    ///
    /// # Requirements
    ///
    /// Library: libsgx_tcrypto.a
    ///
    /// # Return value
    ///
    /// The 256-bit hash that has been SHA256 calculated
    ///
    /// # Errors
    ///
    /// **SGX_ERROR_INVALID_PARAMETER**
    ///
    /// The pointer is invalid.
    ///
    /// **SGX_ERROR_INVALID_STATE**
    ///
    /// The SHA256 state is not initialized.
    ///
    /// **SGX_ERROR_UNEXPECTED**
    ///
    /// The SHA256 state passed in is likely problematic causing an internal cryptography library failure.
    ///
    pub fn get_hash(&self) -> SgxResult<sgx_sha256_hash_t> {
        if !self.initflag.get() {
            return Err(sgx_status_t::SGX_ERROR_INVALID_STATE);
        }

        let mut hash = sgx_sha256_hash_t::default();
        let ret = rsgx_sha256_get_hash(*self.handle.borrow(), &mut hash);
        match ret {
            sgx_status_t::SGX_SUCCESS => Ok(hash),
            _ => Err(ret),
        }
    }

    ///
    /// close cleans up and deallocates the SHA256 state that was allocated in function init.
    ///
    /// # Description
    ///
    /// Calling close is the last step after performing a SHA256 hash over multiple datasets.
    /// The caller uses this function to deallocate memory used to store the SHA256 calculation state.
    ///
    /// # Requirements
    ///
    /// Library: libsgx_tcrypto.a
    ///
    /// # Errors
    ///
    /// **SGX_ERROR_INVALID_PARAMETER**
    ///
    /// The input handle is invalid.
    ///
    pub fn close(&self) -> SgxError {
        if !self.initflag.get() {
            return Ok(());
        }

        let ret = {
            let handle = *self.handle.borrow();
            if handle.is_null() {
                sgx_status_t::SGX_SUCCESS
            } else {
                rsgx_sha256_close(handle)
            }
        };

        match ret {
            sgx_status_t::SGX_SUCCESS => {
                self.initflag.set(false);
                *self.handle.borrow_mut() = ptr::null_mut();
                Ok(())
            }
            _ => Err(ret),
        }
    }
}

impl Default for SgxShaHandle {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for SgxShaHandle {
    ///
    /// drop cleans up and deallocates the SHA256 state that was allocated in function init.
    ///
    fn drop(&mut self) {
        let _ = self.close();
    }
}
