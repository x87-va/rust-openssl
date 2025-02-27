//! Describe a context in which to verify an `X509` certificate.
//!
//! The `X509` certificate store holds trusted CA certificates used to verify
//! peer certificates.
//!
//! # Example
//!
//! ```rust
//! use openssl::x509::store::{X509StoreBuilder, X509Store};
//! use openssl::x509::{X509, X509Name};
//! use openssl::pkey::PKey;
//! use openssl::hash::MessageDigest;
//! use openssl::rsa::Rsa;
//! use openssl::nid::Nid;
//!
//! let rsa = Rsa::generate(2048).unwrap();
//! let pkey = PKey::from_rsa(rsa).unwrap();
//!
//! let mut name = X509Name::builder().unwrap();
//! name.append_entry_by_nid(Nid::COMMONNAME, "foobar.com").unwrap();
//! let name = name.build();
//!
//! let mut builder = X509::builder().unwrap();
//! builder.set_version(2).unwrap();
//! builder.set_subject_name(&name).unwrap();
//! builder.set_issuer_name(&name).unwrap();
//! builder.set_pubkey(&pkey).unwrap();
//! builder.sign(&pkey, MessageDigest::sha256()).unwrap();
//!
//! let certificate: X509 = builder.build();
//!
//! let mut builder = X509StoreBuilder::new().unwrap();
//! let _ = builder.add_cert(&certificate);
//!
//! let store: X509Store = builder.build();
//! ```

use cfg_if::cfg_if;
use foreign_types::ForeignTypeRef;
use std::mem;

use crate::error::ErrorStack;
use crate::stack::StackRef;
use crate::x509::crl::X509CRLRef;
#[cfg(any(ossl102, libressl261))]
use crate::x509::verify::{X509VerifyFlags, X509VerifyParamRef};
use crate::x509::{X509Object, X509Ref};
use crate::{cvt, cvt_p};

foreign_type_and_impl_send_sync! {
    type CType = ffi::X509_STORE;
    fn drop = ffi::X509_STORE_free;

    /// A builder type used to construct an `X509Store`.
    pub struct X509StoreBuilder;
    /// Reference to an `X509StoreBuilder`.
    pub struct X509StoreBuilderRef;
}

impl X509StoreBuilder {
    /// Returns a builder for a certificate store.
    ///
    /// The store is initially empty.
    pub fn new() -> Result<X509StoreBuilder, ErrorStack> {
        unsafe {
            ffi::init();

            cvt_p(ffi::X509_STORE_new()).map(X509StoreBuilder)
        }
    }

    /// Constructs the `X509Store`.
    pub fn build(self) -> X509Store {
        let store = X509Store(self.0);
        mem::forget(self);
        store
    }
}

impl X509StoreBuilderRef {
    /// Adds a certificate to the certificate store.
    pub fn add_cert(&mut self, cert: &X509Ref) -> Result<(), ErrorStack> {
        unsafe { cvt(ffi::X509_STORE_add_cert(self.as_ptr(), cert.as_ptr())).map(|_| ()) }
    }

    /// Adds a CRL to the certificate store.
    pub fn add_crl(&mut self, crl: &X509CRLRef) -> Result<(), ErrorStack> {
        unsafe { cvt(ffi::X509_STORE_add_crl(self.as_ptr(), crl.as_ptr())).map(|_| ()) }
    }

    /// Load certificates from their default locations.
    ///
    /// These locations are read from the `SSL_CERT_FILE` and `SSL_CERT_DIR`
    /// environment variables if present, or defaults specified at OpenSSL
    /// build time otherwise.
    pub fn set_default_paths(&mut self) -> Result<(), ErrorStack> {
        unsafe { cvt(ffi::X509_STORE_set_default_paths(self.as_ptr())).map(|_| ()) }
    }

    /// Adds a lookup method to the store.
    ///
    /// This corresponds to [`X509_STORE_add_lookup`].
    ///
    /// [`X509_STORE_add_lookup`]: https://www.openssl.org/docs/man1.1.1/man3/X509_STORE_add_lookup.html
    pub fn add_lookup<T>(
        &mut self,
        method: &'static X509LookupMethodRef<T>,
    ) -> Result<&mut X509LookupRef<T>, ErrorStack> {
        let lookup = unsafe { ffi::X509_STORE_add_lookup(self.as_ptr(), method.as_ptr()) };
        cvt_p(lookup).map(|ptr| unsafe { X509LookupRef::from_ptr_mut(ptr) })
    }

    /// Sets certificate chain validation related flags.
    ///
    /// This corresponds to [`X509_STORE_set_flags`].
    ///
    /// [`X509_STORE_set_flags`]: https://www.openssl.org/docs/man1.1.1/man3/X509_STORE_set_flags.html
    #[cfg(any(ossl102, libressl261))]
    pub fn set_flags(&mut self, flags: X509VerifyFlags) -> Result<(), ErrorStack> {
        unsafe { cvt(ffi::X509_STORE_set_flags(self.as_ptr(), flags.bits())).map(|_| ()) }
    }
}

generic_foreign_type_and_impl_send_sync! {
    type CType = ffi::X509_LOOKUP;
    fn drop = ffi::X509_LOOKUP_free;

    /// Information used by an `X509Store` to look up certificates and CRLs.
    pub struct X509Lookup<T>;
    /// Reference to an `X509Lookup`.
    pub struct X509LookupRef<T>;
}

/// Marker type corresponding to the [`X509_LOOKUP_hash_dir`] lookup method.
///
/// [`X509_LOOKUP_hash_dir`]: https://www.openssl.org/docs/man1.1.0/crypto/X509_LOOKUP_hash_dir.html
pub struct HashDir;

impl X509Lookup<HashDir> {
    /// Lookup method that loads certificates and CRLs on demand and caches
    /// them in memory once they are loaded. It also checks for newer CRLs upon
    /// each lookup, so that newer CRLs are used as soon as they appear in the
    /// directory.
    ///
    /// This corresponds to [`X509_LOOKUP_hash_dir`].
    ///
    /// [`X509_LOOKUP_hash_dir`]: https://www.openssl.org/docs/man1.1.0/crypto/X509_LOOKUP_hash_dir.html
    pub fn hash_dir() -> &'static X509LookupMethodRef<HashDir> {
        unsafe { X509LookupMethodRef::from_ptr(ffi::X509_LOOKUP_hash_dir()) }
    }
}

impl X509LookupRef<HashDir> {
    /// Specifies a directory from which certificates and CRLs will be loaded
    /// on-demand. Must be used with `X509Lookup::hash_dir`.
    ///
    /// This corresponds to [`X509_LOOKUP_add_dir`].
    ///
    /// [`X509_LOOKUP_add_dir`]: https://www.openssl.org/docs/man1.1.1/man3/X509_LOOKUP_add_dir.html
    pub fn add_dir(
        &mut self,
        name: &str,
        file_type: crate::ssl::SslFiletype,
    ) -> Result<(), ErrorStack> {
        let name = std::ffi::CString::new(name).unwrap();
        unsafe {
            cvt(ffi::X509_LOOKUP_add_dir(
                self.as_ptr(),
                name.as_ptr(),
                file_type.as_raw(),
            ))
            .map(|_| ())
        }
    }
}

generic_foreign_type_and_impl_send_sync! {
    type CType = ffi::X509_LOOKUP_METHOD;
    fn drop = X509_LOOKUP_meth_free;

    /// Method used to look up certificates and CRLs.
    pub struct X509LookupMethod<T>;
    /// Reference to an `X509LookupMethod`.
    pub struct X509LookupMethodRef<T>;
}

foreign_type_and_impl_send_sync! {
    type CType = ffi::X509_STORE;
    fn drop = ffi::X509_STORE_free;

    /// A certificate store to hold trusted `X509` certificates.
    pub struct X509Store;
    /// Reference to an `X509Store`.
    pub struct X509StoreRef;
}

impl X509StoreRef {
    /// Get a reference to the cache of certificates in this store.
    pub fn objects(&self) -> &StackRef<X509Object> {
        unsafe { StackRef::from_ptr(X509_STORE_get0_objects(self.as_ptr())) }
    }

    /// Sets the verification parameters for store.
    pub fn set_param(&mut self, param: &X509VerifyParamRef) -> Result<(), ErrorStack> {
        unsafe { cvt(ffi::X509_STORE_set1_param(self.as_ptr(), param.as_ptr())).map(|_| ()) }
    }
}

cfg_if! {
    if #[cfg(any(ossl110, libressl270))] {
        use ffi::X509_STORE_get0_objects;
    } else {
        #[allow(bad_style)]
        unsafe fn X509_STORE_get0_objects(x: *mut ffi::X509_STORE) -> *mut ffi::stack_st_X509_OBJECT {
            (*x).objs
        }
    }
}

cfg_if! {
    if #[cfg(ossl110)] {
        use ffi::X509_LOOKUP_meth_free;
    } else {
        #[allow(bad_style)]
        unsafe fn X509_LOOKUP_meth_free(_x: *mut ffi::X509_LOOKUP_METHOD) {}
    }
}
