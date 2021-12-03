use libc::*;

use *;

pub enum PKCS7_SIGNED {}
pub enum PKCS7_ENVELOPE {}
pub enum PKCS7_SIGN_ENVELOPE {}
pub enum PKCS7_DIGEST {}
pub enum PKCS7_ENCRYPT {}
pub enum PKCS7 {}

pub const PKCS7_TEXT: c_int = 0x1;
pub const PKCS7_NOCERTS: c_int = 0x2;
pub const PKCS7_NOSIGS: c_int = 0x4;
pub const PKCS7_NOCHAIN: c_int = 0x8;
pub const PKCS7_NOINTERN: c_int = 0x10;
pub const PKCS7_NOVERIFY: c_int = 0x20;
pub const PKCS7_DETACHED: c_int = 0x40;
pub const PKCS7_BINARY: c_int = 0x80;
pub const PKCS7_NOATTR: c_int = 0x100;
pub const PKCS7_NOSMIMECAP: c_int = 0x200;
pub const PKCS7_NOOLDMIMETYPE: c_int = 0x400;
pub const PKCS7_CRLFEOL: c_int = 0x800;
pub const PKCS7_STREAM: c_int = 0x1000;
pub const PKCS7_NOCRL: c_int = 0x2000;
pub const PKCS7_PARTIAL: c_int = 0x4000;
pub const PKCS7_REUSE_DIGEST: c_int = 0x8000;
#[cfg(not(any(ossl101, ossl102, libressl)))]
pub const PKCS7_NO_DUAL_CONTENT: c_int = 0x10000;

#[repr(C)]
pub struct PKCS7_ISSUER_AND_SERIAL {
    pub issuer: *mut X509_NAME,
    pub serial: *mut ASN1_INTEGER,
}

#[repr(C)]
pub struct PKCS7_SIGNER_INFO {
    pub version: *mut ASN1_INTEGER, // version 1
    pub issuer_and_serial: *mut PKCS7_ISSUER_AND_SERIAL,
    pub digest_alg: *mut X509_ALGOR,
    pub auth_attr: *mut stack_st_X509_ATTRIBUTE, // [ 0 ]
    pub digest_enc_alg: *mut X509_ALGOR,
    pub enc_digest: *mut ASN1_OCTET_STRING,
    pub unauth_attr: *mut stack_st_X509_ATTRIBUTE, // [ 1 ]
    pub pkey: *mut EVP_PKEY,                       // The private key to sign with
}

extern "C" {
    pub fn d2i_PKCS7(a: *mut *mut PKCS7, pp: *mut *const c_uchar, length: c_long) -> *mut PKCS7;
}

const_ptr_api! {
    extern "C" {
        pub fn i2d_PKCS7(a: #[const_ptr_if(ossl300)] PKCS7, buf: *mut *mut u8) -> c_int;
    }
}

extern "C" {
    pub fn PKCS7_encrypt(
        certs: *mut stack_st_X509,
        b: *mut BIO,
        cipher: *const EVP_CIPHER,
        flags: c_int,
    ) -> *mut PKCS7;

    pub fn PKCS7_verify(
        pkcs7: *mut PKCS7,
        certs: *mut stack_st_X509,
        store: *mut X509_STORE,
        indata: *mut BIO,
        out: *mut BIO,
        flags: c_int,
    ) -> c_int;

    pub fn PKCS7_get0_signers(
        pkcs7: *mut PKCS7,
        certs: *mut stack_st_X509,
        flags: c_int,
    ) -> *mut stack_st_X509;

    pub fn PKCS7_sign(
        signcert: *mut X509,
        pkey: *mut EVP_PKEY,
        certs: *mut stack_st_X509,
        data: *mut BIO,
        flags: c_int,
    ) -> *mut PKCS7;

    pub fn PKCS7_decrypt(
        pkcs7: *mut PKCS7,
        pkey: *mut EVP_PKEY,
        cert: *mut X509,
        data: *mut BIO,
        flags: c_int,
    ) -> c_int;

    pub fn PKCS7_free(pkcs7: *mut PKCS7);

    pub fn SMIME_write_PKCS7(
        out: *mut BIO,
        pkcs7: *mut PKCS7,
        data: *mut BIO,
        flags: c_int,
    ) -> c_int;

    pub fn SMIME_read_PKCS7(bio: *mut BIO, bcont: *mut *mut BIO) -> *mut PKCS7;
}
