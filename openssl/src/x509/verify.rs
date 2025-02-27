use std::net::IpAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bitflags::bitflags;
use foreign_types::ForeignTypeRef;
use libc::{c_int, c_uint, c_ulong, time_t};

use crate::error::ErrorStack;
use crate::{cvt, cvt_p};

bitflags! {
    /// Flags used to check an `X509` certificate.
    pub struct X509CheckFlags: c_uint {
        const ALWAYS_CHECK_SUBJECT = ffi::X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT;
        const NO_WILDCARDS = ffi::X509_CHECK_FLAG_NO_WILDCARDS;
        const NO_PARTIAL_WILDCARDS = ffi::X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS;
        const MULTI_LABEL_WILDCARDS = ffi::X509_CHECK_FLAG_MULTI_LABEL_WILDCARDS;
        const SINGLE_LABEL_SUBDOMAINS = ffi::X509_CHECK_FLAG_SINGLE_LABEL_SUBDOMAINS;
        /// Requires OpenSSL 1.1.0 or newer.
        #[cfg(any(ossl110))]
        const NEVER_CHECK_SUBJECT = ffi::X509_CHECK_FLAG_NEVER_CHECK_SUBJECT;

        #[deprecated(since = "0.10.6", note = "renamed to NO_WILDCARDS")]
        const FLAG_NO_WILDCARDS = ffi::X509_CHECK_FLAG_NO_WILDCARDS;
    }
}

bitflags! {
    /// Flags used to verify an `X509` certificate chain.
    pub struct X509VerifyFlags: c_ulong {
        const CB_ISSUER_CHECK = ffi::X509_V_FLAG_CB_ISSUER_CHECK;
        const USE_CHECK_TIME = ffi::X509_V_FLAG_USE_CHECK_TIME;
        const CRL_CHECK = ffi::X509_V_FLAG_CRL_CHECK;
        const CRL_CHECK_ALL = ffi::X509_V_FLAG_CRL_CHECK_ALL;
        const IGNORE_CRITICAL = ffi::X509_V_FLAG_IGNORE_CRITICAL;
        const X509_STRICT = ffi::X509_V_FLAG_X509_STRICT;
        const ALLOW_PROXY_CERTS = ffi::X509_V_FLAG_ALLOW_PROXY_CERTS;
        const POLICY_CHECK = ffi::X509_V_FLAG_POLICY_CHECK;
        const EXPLICIT_POLICY = ffi::X509_V_FLAG_EXPLICIT_POLICY;
        const INHIBIT_ANY = ffi::X509_V_FLAG_INHIBIT_ANY;
        const INHIBIT_MAP = ffi::X509_V_FLAG_INHIBIT_MAP;
        const NOTIFY_POLICY = ffi::X509_V_FLAG_NOTIFY_POLICY;
        const EXTENDED_CRL_SUPPORT = ffi::X509_V_FLAG_EXTENDED_CRL_SUPPORT;
        const USE_DELTAS = ffi::X509_V_FLAG_USE_DELTAS;
        const CHECK_SS_SIGNATURE = ffi::X509_V_FLAG_CHECK_SS_SIGNATURE;
        #[cfg(ossl102)]
        const TRUSTED_FIRST = ffi::X509_V_FLAG_TRUSTED_FIRST;
        #[cfg(ossl102)]
        const SUITEB_128_LOS_ONLY = ffi::X509_V_FLAG_SUITEB_128_LOS_ONLY;
        #[cfg(ossl102)]
        const SUITEB_192_LOS = ffi::X509_V_FLAG_SUITEB_128_LOS;
        #[cfg(ossl102)]
        const SUITEB_128_LOS = ffi::X509_V_FLAG_SUITEB_192_LOS;
        #[cfg(ossl102)]
        const PARTIAL_CHAIN = ffi::X509_V_FLAG_PARTIAL_CHAIN;
        #[cfg(ossl110)]
        const NO_ALT_CHAINS = ffi::X509_V_FLAG_NO_ALT_CHAINS;
        #[cfg(ossl110)]
        const NO_CHECK_TIME = ffi::X509_V_FLAG_NO_CHECK_TIME;
    }
}

foreign_type_and_impl_send_sync! {
    type CType = ffi::X509_VERIFY_PARAM;
    fn drop = ffi::X509_VERIFY_PARAM_free;

    /// Adjust parameters associated with certificate verification.
    pub struct X509VerifyParam;
    /// Reference to `X509VerifyParam`.
    pub struct X509VerifyParamRef;
}

impl X509VerifyParam {
    pub fn new() -> Result<X509VerifyParam, ErrorStack> {
        unsafe { cvt_p(ffi::X509_VERIFY_PARAM_new()).map(X509VerifyParam) }
    }
}

impl X509VerifyParamRef {
    /// Set the host flags.
    ///
    /// This corresponds to [`X509_VERIFY_PARAM_set_hostflags`].
    ///
    /// [`X509_VERIFY_PARAM_set_hostflags`]: https://www.openssl.org/docs/man1.1.0/crypto/X509_VERIFY_PARAM_set_hostflags.html
    pub fn set_hostflags(&mut self, hostflags: X509CheckFlags) {
        unsafe {
            ffi::X509_VERIFY_PARAM_set_hostflags(self.as_ptr(), hostflags.bits);
        }
    }

    /// Set verification flags.
    ///
    /// This corresponds to [`X509_VERIFY_PARAM_set_flags`].
    ///
    /// [`X509_VERIFY_PARAM_set_flags`]: https://www.openssl.org/docs/man1.0.2/crypto/X509_VERIFY_PARAM_set_flags.html
    pub fn set_flags(&mut self, flags: X509VerifyFlags) -> Result<(), ErrorStack> {
        unsafe { cvt(ffi::X509_VERIFY_PARAM_set_flags(self.as_ptr(), flags.bits)).map(|_| ()) }
    }

    /// Clear verification flags.
    ///
    /// This corresponds to [`X509_VERIFY_PARAM_clear_flags`].
    ///
    /// [`X509_VERIFY_PARAM_clear_flags`]: https://www.openssl.org/docs/man1.0.2/crypto/X509_VERIFY_PARAM_clear_flags.html
    pub fn clear_flags(&mut self, flags: X509VerifyFlags) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::X509_VERIFY_PARAM_clear_flags(
                self.as_ptr(),
                flags.bits,
            ))
            .map(|_| ())
        }
    }

    /// Gets verification flags.
    ///
    /// This corresponds to [`X509_VERIFY_PARAM_get_flags`].
    ///
    /// [`X509_VERIFY_PARAM_get_flags`]: https://www.openssl.org/docs/man1.0.2/crypto/X509_VERIFY_PARAM_get_flags.html
    pub fn flags(&mut self) -> X509VerifyFlags {
        let bits = unsafe { ffi::X509_VERIFY_PARAM_get_flags(self.as_ptr()) };
        X509VerifyFlags { bits }
    }

    /// Set the expected DNS hostname.
    ///
    /// This corresponds to [`X509_VERIFY_PARAM_set1_host`].
    ///
    /// [`X509_VERIFY_PARAM_set1_host`]: https://www.openssl.org/docs/man1.1.0/crypto/X509_VERIFY_PARAM_set1_host.html
    pub fn set_host(&mut self, host: &str) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::X509_VERIFY_PARAM_set1_host(
                self.as_ptr(),
                host.as_ptr() as *const _,
                host.len(),
            ))
            .map(|_| ())
        }
    }

    /// Set the expected IPv4 or IPv6 address.
    ///
    /// This corresponds to [`X509_VERIFY_PARAM_set1_ip`].
    ///
    /// [`X509_VERIFY_PARAM_set1_ip`]: https://www.openssl.org/docs/man1.1.0/crypto/X509_VERIFY_PARAM_set1_ip.html
    pub fn set_ip(&mut self, ip: IpAddr) -> Result<(), ErrorStack> {
        unsafe {
            let mut buf = [0; 16];

            let len = match ip {
                IpAddr::V4(addr) => {
                    buf[..4].copy_from_slice(&addr.octets());
                    4
                }
                IpAddr::V6(addr) => {
                    buf.copy_from_slice(&addr.octets());
                    16
                }
            };

            cvt(ffi::X509_VERIFY_PARAM_set1_ip(
                self.as_ptr(),
                buf.as_ptr() as *const _,
                len,
            ))
            .map(|_| ())
        }
    }

    pub fn set_time(&mut self, time: SystemTime) {
        let unix_time = time.duration_since(UNIX_EPOCH).unwrap().as_secs() as time_t;

        unsafe {
            ffi::X509_VERIFY_PARAM_set_time(self.as_ptr(), unix_time);
        }
    }

    pub fn get_time(&self) -> SystemTime {
        let unix_time = unsafe { ffi::X509_VERIFY_PARAM_get_time(self.as_ptr()) };
        UNIX_EPOCH + Duration::from_secs(unix_time as u64)
    }

    pub fn set_depth(&mut self, depth: isize) {
        unsafe { ffi::X509_VERIFY_PARAM_set_depth(self.as_ptr(), depth as c_int) };
    }

    pub fn get_depth(&mut self) -> isize {
        unsafe { ffi::X509_VERIFY_PARAM_get_depth(self.as_ptr()) as isize }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_set_verify_time() {
        let mut param = X509VerifyParam::new().unwrap();
        assert_eq!(UNIX_EPOCH, param.get_time());

        let verify_time = UNIX_EPOCH + Duration::from_secs(1950902108);
        param.set_time(verify_time);

        assert_eq!(verify_time, param.get_time());
    }

    #[test]
    fn get_set_verify_depth() {
        let mut param = X509VerifyParam::new().unwrap();
        assert_eq!(-1, param.get_depth());

        let depth = 2;
        param.set_depth(depth);
        assert_eq!(depth, param.get_depth());
    }
}
