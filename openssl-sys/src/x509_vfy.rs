use libc::*;

use *;

#[cfg(any(libressl, all(ossl102, not(ossl110))))]
pub enum X509_VERIFY_PARAM_ID {}

pub const X509_V_OK: c_int = 0;
#[cfg(ossl102f)]
pub const X509_V_ERR_UNSPECIFIED: c_int = 1;
pub const X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT: c_int = 2;
pub const X509_V_ERR_UNABLE_TO_GET_CRL: c_int = 3;
pub const X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE: c_int = 4;
pub const X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE: c_int = 5;
pub const X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY: c_int = 6;
pub const X509_V_ERR_CERT_SIGNATURE_FAILURE: c_int = 7;
pub const X509_V_ERR_CRL_SIGNATURE_FAILURE: c_int = 8;
pub const X509_V_ERR_CERT_NOT_YET_VALID: c_int = 9;
pub const X509_V_ERR_CERT_HAS_EXPIRED: c_int = 10;
pub const X509_V_ERR_CRL_NOT_YET_VALID: c_int = 11;
pub const X509_V_ERR_CRL_HAS_EXPIRED: c_int = 12;
pub const X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD: c_int = 13;
pub const X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD: c_int = 14;
pub const X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD: c_int = 15;
pub const X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD: c_int = 16;
pub const X509_V_ERR_OUT_OF_MEM: c_int = 17;
pub const X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT: c_int = 18;
pub const X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN: c_int = 19;
pub const X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY: c_int = 20;
pub const X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE: c_int = 21;
pub const X509_V_ERR_CERT_CHAIN_TOO_LONG: c_int = 22;
pub const X509_V_ERR_CERT_REVOKED: c_int = 23;
cfg_if! {
    if #[cfg(ossl300)] {
        pub const X509_V_ERR_NO_ISSUER_PUBLIC_KEY: c_int = 24;
    } else {
        pub const X509_V_ERR_INVALID_CA: c_int = 24;
    }
}
pub const X509_V_ERR_PATH_LENGTH_EXCEEDED: c_int = 25;
pub const X509_V_ERR_INVALID_PURPOSE: c_int = 26;
pub const X509_V_ERR_CERT_UNTRUSTED: c_int = 27;
pub const X509_V_ERR_CERT_REJECTED: c_int = 28;
pub const X509_V_ERR_SUBJECT_ISSUER_MISMATCH: c_int = 29;
pub const X509_V_ERR_AKID_SKID_MISMATCH: c_int = 30;
pub const X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH: c_int = 31;
pub const X509_V_ERR_KEYUSAGE_NO_CERTSIGN: c_int = 32;
pub const X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER: c_int = 33;
pub const X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION: c_int = 34;
pub const X509_V_ERR_KEYUSAGE_NO_CRL_SIGN: c_int = 35;
pub const X509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION: c_int = 36;
pub const X509_V_ERR_INVALID_NON_CA: c_int = 37;
pub const X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED: c_int = 38;
pub const X509_V_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE: c_int = 39;
pub const X509_V_ERR_PROXY_CERTIFICATES_NOT_ALLOWED: c_int = 40;
pub const X509_V_ERR_INVALID_EXTENSION: c_int = 41;
pub const X509_V_ERR_INVALID_POLICY_EXTENSION: c_int = 42;
pub const X509_V_ERR_NO_EXPLICIT_POLICY: c_int = 43;
pub const X509_V_ERR_DIFFERENT_CRL_SCOPE: c_int = 44;
pub const X509_V_ERR_UNSUPPORTED_EXTENSION_FEATURE: c_int = 45;
pub const X509_V_ERR_UNNESTED_RESOURCE: c_int = 46;
pub const X509_V_ERR_PERMITTED_VIOLATION: c_int = 47;
pub const X509_V_ERR_EXCLUDED_VIOLATION: c_int = 48;
pub const X509_V_ERR_SUBTREE_MINMAX: c_int = 49;
pub const X509_V_ERR_APPLICATION_VERIFICATION: c_int = 50;
pub const X509_V_ERR_UNSUPPORTED_CONSTRAINT_TYPE: c_int = 51;
pub const X509_V_ERR_UNSUPPORTED_CONSTRAINT_SYNTAX: c_int = 52;
pub const X509_V_ERR_UNSUPPORTED_NAME_SYNTAX: c_int = 53;
pub const X509_V_ERR_CRL_PATH_VALIDATION_ERROR: c_int = 54;
#[cfg(ossl102)]
pub const X509_V_ERR_SUITE_B_INVALID_VERSION: c_int = 56;
#[cfg(ossl102)]
pub const X509_V_ERR_SUITE_B_INVALID_ALGORITHM: c_int = 57;
#[cfg(ossl102)]
pub const X509_V_ERR_SUITE_B_INVALID_CURVE: c_int = 58;
#[cfg(ossl102)]
pub const X509_V_ERR_SUITE_B_INVALID_SIGNATURE_ALGORITHM: c_int = 59;
#[cfg(ossl102)]
pub const X509_V_ERR_SUITE_B_LOS_NOT_ALLOWED: c_int = 60;
#[cfg(ossl102)]
pub const X509_V_ERR_SUITE_B_CANNOT_SIGN_P_384_WITH_P_256: c_int = 61;
#[cfg(ossl102)]
pub const X509_V_ERR_HOSTNAME_MISMATCH: c_int = 62;
#[cfg(ossl102)]
pub const X509_V_ERR_EMAIL_MISMATCH: c_int = 63;
#[cfg(ossl102)]
pub const X509_V_ERR_IP_ADDRESS_MISMATCH: c_int = 64;
cfg_if! {
    if #[cfg(ossl110)] {
        pub const X509_V_ERR_DANE_NO_MATCH: c_int = 65;
        pub const X509_V_ERR_EE_KEY_TOO_SMALL: c_int = 66;
        pub const X509_V_ERR_CA_KEY_TOO_SMALL: c_int = 67;
        pub const X509_V_ERR_CA_MD_TOO_WEAK: c_int = 68;
        pub const X509_V_ERR_INVALID_CALL: c_int = 69;
        pub const X509_V_ERR_STORE_LOOKUP: c_int = 70;
        pub const X509_V_ERR_NO_VALID_SCTS: c_int = 71;
    } else if #[cfg(ossl102h)] {
        pub const X509_V_ERR_INVALID_CALL: c_int = 65;
        pub const X509_V_ERR_STORE_LOOKUP: c_int = 66;
        pub const X509_V_ERR_PROXY_SUBJECT_NAME_VIOLATION: c_int = 67;
    }
}

#[cfg(not(ossl110))]
pub const X509_V_FLAG_CB_ISSUER_CHECK: c_ulong = 0x1;
#[cfg(ossl110)]
pub const X509_V_FLAG_CB_ISSUER_CHECK: c_ulong = 0x0;
pub const X509_V_FLAG_USE_CHECK_TIME: c_ulong = 0x2;
pub const X509_V_FLAG_CRL_CHECK: c_ulong = 0x4;
pub const X509_V_FLAG_CRL_CHECK_ALL: c_ulong = 0x8;
pub const X509_V_FLAG_IGNORE_CRITICAL: c_ulong = 0x10;
pub const X509_V_FLAG_X509_STRICT: c_ulong = 0x20;
pub const X509_V_FLAG_ALLOW_PROXY_CERTS: c_ulong = 0x40;
pub const X509_V_FLAG_POLICY_CHECK: c_ulong = 0x80;
pub const X509_V_FLAG_EXPLICIT_POLICY: c_ulong = 0x100;
pub const X509_V_FLAG_INHIBIT_ANY: c_ulong = 0x200;
pub const X509_V_FLAG_INHIBIT_MAP: c_ulong = 0x400;
pub const X509_V_FLAG_NOTIFY_POLICY: c_ulong = 0x800;
pub const X509_V_FLAG_EXTENDED_CRL_SUPPORT: c_ulong = 0x1000;
pub const X509_V_FLAG_USE_DELTAS: c_ulong = 0x2000;
pub const X509_V_FLAG_CHECK_SS_SIGNATURE: c_ulong = 0x4000;
#[cfg(ossl102)]
pub const X509_V_FLAG_TRUSTED_FIRST: c_ulong = 0x8000;
#[cfg(ossl102)]
pub const X509_V_FLAG_SUITEB_128_LOS_ONLY: c_ulong = 0x10000;
#[cfg(ossl102)]
pub const X509_V_FLAG_SUITEB_192_LOS: c_ulong = 0x20000;
#[cfg(ossl102)]
pub const X509_V_FLAG_SUITEB_128_LOS: c_ulong = 0x30000;
#[cfg(ossl102)]
pub const X509_V_FLAG_PARTIAL_CHAIN: c_ulong = 0x80000;
#[cfg(ossl110)]
pub const X509_V_FLAG_NO_ALT_CHAINS: c_ulong = 0x100000;
#[cfg(ossl110)]
pub const X509_V_FLAG_NO_CHECK_TIME: c_ulong = 0x200000;

extern "C" {
    #[cfg(ossl110)]
    pub fn X509_LOOKUP_meth_free(method: *mut X509_LOOKUP_METHOD);
}

extern "C" {
    pub fn X509_LOOKUP_free(ctx: *mut X509_LOOKUP);
    pub fn X509_LOOKUP_hash_dir() -> *mut X509_LOOKUP_METHOD;
    pub fn X509_LOOKUP_ctrl(
        ctx: *mut X509_LOOKUP,
        cmd: c_int,
        argc: *const c_char,
        argl: c_long,
        ret: *mut *mut c_char,
    ) -> c_int;
}

pub unsafe fn X509_LOOKUP_add_dir(
    ctx: *mut X509_LOOKUP,
    name: *const c_char,
    _type: c_int,
) -> c_int {
    const X509_L_ADD_DIR: c_int = 2;
    X509_LOOKUP_ctrl(
        ctx,
        X509_L_ADD_DIR,
        name,
        _type as c_long,
        std::ptr::null_mut(),
    )
}

extern "C" {
    pub fn X509_STORE_CTX_new() -> *mut X509_STORE_CTX;

    pub fn X509_STORE_CTX_free(ctx: *mut X509_STORE_CTX);

    pub fn X509_STORE_CTX_init(
        ctx: *mut X509_STORE_CTX,
        store: *mut X509_STORE,
        x509: *mut X509,
        chain: *mut stack_st_X509,
    ) -> c_int;

    pub fn X509_STORE_CTX_cleanup(ctx: *mut X509_STORE_CTX);

    pub fn X509_STORE_CTX_set_error(ctx: *mut X509_STORE_CTX, error: c_int);

    pub fn X509_STORE_CTX_set0_param(ctx: *mut X509_STORE_CTX, param: *mut X509_VERIFY_PARAM);
}

extern "C" {
    pub fn X509_STORE_new() -> *mut X509_STORE;

    pub fn X509_STORE_free(store: *mut X509_STORE);

    pub fn X509_STORE_add_cert(store: *mut X509_STORE, x: *mut X509) -> c_int;

    pub fn X509_STORE_add_crl(store: *mut X509_STORE, x: *mut X509_CRL) -> c_int;

    pub fn X509_STORE_add_lookup(
        store: *mut X509_STORE,
        meth: *mut X509_LOOKUP_METHOD,
    ) -> *mut X509_LOOKUP;

    pub fn X509_STORE_set_default_paths(store: *mut X509_STORE) -> c_int;

    pub fn X509_STORE_set_flags(store: *mut X509_STORE, flags: c_ulong) -> c_int;
}

const_ptr_api! {
    extern "C" {
        pub fn X509_STORE_CTX_get0_param(ctx: #[const_ptr_if(ossl300)] X509_STORE_CTX) -> *mut X509_VERIFY_PARAM;
        pub fn X509_STORE_set1_param(store: *mut X509_STORE, param: #[const_ptr_if(ossl300)] X509_VERIFY_PARAM) -> c_int;

        pub fn X509_STORE_CTX_get_ex_data(ctx: #[const_ptr_if(ossl300)] X509_STORE_CTX, idx: c_int) -> *mut c_void;
        pub fn X509_STORE_CTX_get_error(ctx: #[const_ptr_if(ossl300)] X509_STORE_CTX) -> c_int;
        pub fn X509_STORE_CTX_get_error_depth(ctx: #[const_ptr_if(ossl300)] X509_STORE_CTX) -> c_int;
        pub fn X509_STORE_CTX_get_current_cert(ctx: #[const_ptr_if(ossl300)] X509_STORE_CTX) -> *mut X509;
    }
}

cfg_if! {
    if #[cfg(ossl110)] {
        const_ptr_api! {
            extern "C" {
                pub fn X509_STORE_CTX_get0_chain(ctx: #[const_ptr_if(ossl300)] X509_STORE_CTX) -> *mut stack_st_X509;
            }
        }
    } else {
        extern "C" {
            pub fn X509_STORE_CTX_get_chain(ctx: *mut X509_STORE_CTX) -> *mut stack_st_X509;
        }
    }
}

extern "C" {
    #[cfg(any(ossl102, libressl261))]
    pub fn X509_VERIFY_PARAM_new() -> *mut X509_VERIFY_PARAM;

    #[cfg(any(ossl102, libressl261))]
    pub fn X509_VERIFY_PARAM_free(param: *mut X509_VERIFY_PARAM);

    #[cfg(any(ossl102, libressl261))]
    pub fn X509_VERIFY_PARAM_set_flags(param: *mut X509_VERIFY_PARAM, flags: c_ulong) -> c_int;

    #[cfg(any(ossl102, libressl261))]
    pub fn X509_VERIFY_PARAM_clear_flags(param: *mut X509_VERIFY_PARAM, flags: c_ulong) -> c_int;

    #[cfg(any(ossl102, libressl261))]
    pub fn X509_VERIFY_PARAM_set_time(param: *mut X509_VERIFY_PARAM, time: time_t);

    #[cfg(any(ossl102, libressl261))]
    pub fn X509_VERIFY_PARAM_set_depth(ctx: *mut X509_VERIFY_PARAM, depth: c_int);

    #[cfg(any(ossl102, libressl261))]
    pub fn X509_VERIFY_PARAM_set1_host(
        param: *mut X509_VERIFY_PARAM,
        name: *const c_char,
        namelen: size_t,
    ) -> c_int;

    #[cfg(any(ossl102, libressl261))]
    pub fn X509_VERIFY_PARAM_set_hostflags(param: *mut X509_VERIFY_PARAM, flags: c_uint);

    #[cfg(any(ossl102, libressl261))]
    pub fn X509_VERIFY_PARAM_set1_ip(
        param: *mut X509_VERIFY_PARAM,
        ip: *const c_uchar,
        iplen: size_t,
    ) -> c_int;
}

const_ptr_api! {
    extern "C" {
        #[cfg(any(ossl102, libressl261))]
        pub fn X509_VERIFY_PARAM_get_flags(param: #[const_ptr_if(ossl300)] X509_VERIFY_PARAM) -> c_ulong;

        #[cfg(any(ossl102, libressl261))]
        pub fn X509_VERIFY_PARAM_get_time(param: #[const_ptr_if(ossl102)] X509_VERIFY_PARAM) -> time_t;

        #[cfg(any(ossl102, libressl261))]
        pub fn X509_VERIFY_PARAM_get_depth(param: #[const_ptr_if(ossl102)] X509_VERIFY_PARAM) -> c_int;
    }
}
