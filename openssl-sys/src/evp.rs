use libc::*;
use *;

pub const EVP_MAX_MD_SIZE: c_uint = 64;

pub const PKCS5_SALT_LEN: c_int = 8;
pub const PKCS12_DEFAULT_ITER: c_int = 2048;

pub const EVP_PKEY_RSA: c_int = NID_rsaEncryption;
pub const EVP_PKEY_DSA: c_int = NID_dsa;
pub const EVP_PKEY_DH: c_int = NID_dhKeyAgreement;
pub const EVP_PKEY_EC: c_int = NID_X9_62_id_ecPublicKey;
#[cfg(ossl111)]
pub const EVP_PKEY_X25519: c_int = NID_X25519;
#[cfg(ossl111)]
pub const EVP_PKEY_ED25519: c_int = NID_ED25519;
#[cfg(ossl111)]
pub const EVP_PKEY_X448: c_int = NID_X448;
#[cfg(ossl111)]
pub const EVP_PKEY_ED448: c_int = NID_ED448;
pub const EVP_PKEY_HMAC: c_int = NID_hmac;
pub const EVP_PKEY_CMAC: c_int = NID_cmac;

pub const EVP_CTRL_GCM_SET_IVLEN: c_int = 0x9;
pub const EVP_CTRL_GCM_GET_TAG: c_int = 0x10;
pub const EVP_CTRL_GCM_SET_TAG: c_int = 0x11;

pub unsafe fn EVP_get_digestbynid(type_: c_int) -> *const EVP_MD {
    EVP_get_digestbyname(OBJ_nid2sn(type_))
}

cfg_if! {
    if #[cfg(ossl300)] {
        extern "C" {
            pub fn EVP_MD_get_size(md: *const EVP_MD) -> c_int;
            pub fn EVP_MD_get_type(md: *const EVP_MD) -> c_int;

            pub fn EVP_CIPHER_get_key_length(cipher: *const EVP_CIPHER) -> c_int;
            pub fn EVP_CIPHER_get_block_size(cipher: *const EVP_CIPHER) -> c_int;
            pub fn EVP_CIPHER_get_iv_length(cipher: *const EVP_CIPHER) -> c_int;
            pub fn EVP_CIPHER_get_nid(cipher: *const EVP_CIPHER) -> c_int;
        }

        #[inline]
        pub unsafe fn EVP_MD_size(md: *const EVP_MD) -> c_int {
            EVP_MD_get_size(md)
        }

        #[inline]
        pub unsafe fn EVP_MD_type(md: *const EVP_MD) -> c_int {
            EVP_MD_get_type(md)
        }

        #[inline]
        pub unsafe fn EVP_CIPHER_key_length(cipher: *const EVP_CIPHER) -> c_int {
            EVP_CIPHER_get_key_length(cipher)
        }

        #[inline]
        pub unsafe fn EVP_CIPHER_block_size(cipher: *const EVP_CIPHER) -> c_int {
            EVP_CIPHER_get_block_size(cipher)
        }

        #[inline]
        pub unsafe fn EVP_CIPHER_iv_length(cipher: *const EVP_CIPHER) -> c_int {
            EVP_CIPHER_get_iv_length(cipher)
        }

        #[inline]
        pub unsafe fn EVP_CIPHER_nid(cipher: *const EVP_CIPHER) -> c_int {
            EVP_CIPHER_get_nid(cipher)
        }
    } else {
        extern "C" {
            pub fn EVP_MD_size(md: *const EVP_MD) -> c_int;
            pub fn EVP_MD_type(md: *const EVP_MD) -> c_int;

            pub fn EVP_CIPHER_key_length(cipher: *const EVP_CIPHER) -> c_int;
            pub fn EVP_CIPHER_block_size(cipher: *const EVP_CIPHER) -> c_int;
            pub fn EVP_CIPHER_iv_length(cipher: *const EVP_CIPHER) -> c_int;
            pub fn EVP_CIPHER_nid(cipher: *const EVP_CIPHER) -> c_int;
        }
    }
}
extern "C" {}

cfg_if! {
    if #[cfg(ossl110)] {
        extern "C" {
            pub fn EVP_MD_CTX_new() -> *mut EVP_MD_CTX;
            pub fn EVP_MD_CTX_free(ctx: *mut EVP_MD_CTX);
        }
    } else {
        extern "C" {
            pub fn EVP_MD_CTX_create() -> *mut EVP_MD_CTX;
            pub fn EVP_MD_CTX_destroy(ctx: *mut EVP_MD_CTX);
        }
    }
}

extern "C" {
    pub fn EVP_DigestInit_ex(ctx: *mut EVP_MD_CTX, typ: *const EVP_MD, imple: *mut ENGINE)
        -> c_int;
    pub fn EVP_DigestUpdate(ctx: *mut EVP_MD_CTX, data: *const c_void, n: size_t) -> c_int;
    pub fn EVP_DigestFinal_ex(ctx: *mut EVP_MD_CTX, res: *mut u8, n: *mut u32) -> c_int;
    #[cfg(ossl300)]
    pub fn EVP_Q_digest(
        libctx: *mut OSSL_LIB_CTX,
        name: *const c_char,
        propq: *const c_char,
        data: *const c_void,
        count: size_t,
        md: *mut c_uchar,
        size: *mut size_t,
    ) -> c_int;
    pub fn EVP_DigestInit(ctx: *mut EVP_MD_CTX, typ: *const EVP_MD) -> c_int;
    pub fn EVP_DigestFinal(ctx: *mut EVP_MD_CTX, res: *mut u8, n: *mut u32) -> c_int;
    #[cfg(ossl111)]
    pub fn EVP_DigestFinalXOF(ctx: *mut EVP_MD_CTX, res: *mut u8, len: usize) -> c_int;

    pub fn EVP_BytesToKey(
        typ: *const EVP_CIPHER,
        md: *const EVP_MD,
        salt: *const u8,
        data: *const u8,
        datalen: c_int,
        count: c_int,
        key: *mut u8,
        iv: *mut u8,
    ) -> c_int;

    pub fn EVP_CipherInit(
        ctx: *mut EVP_CIPHER_CTX,
        evp: *const EVP_CIPHER,
        key: *const u8,
        iv: *const u8,
        mode: c_int,
    ) -> c_int;
    pub fn EVP_CipherInit_ex(
        ctx: *mut EVP_CIPHER_CTX,
        type_: *const EVP_CIPHER,
        impl_: *mut ENGINE,
        key: *const c_uchar,
        iv: *const c_uchar,
        enc: c_int,
    ) -> c_int;
    pub fn EVP_CipherUpdate(
        ctx: *mut EVP_CIPHER_CTX,
        outbuf: *mut u8,
        outlen: *mut c_int,
        inbuf: *const u8,
        inlen: c_int,
    ) -> c_int;
    pub fn EVP_CipherFinal(ctx: *mut EVP_CIPHER_CTX, res: *mut u8, len: *mut c_int) -> c_int;

    pub fn EVP_DigestSignInit(
        ctx: *mut EVP_MD_CTX,
        pctx: *mut *mut EVP_PKEY_CTX,
        type_: *const EVP_MD,
        e: *mut ENGINE,
        pkey: *mut EVP_PKEY,
    ) -> c_int;
    pub fn EVP_DigestSignFinal(
        ctx: *mut EVP_MD_CTX,
        sig: *mut c_uchar,
        siglen: *mut size_t,
    ) -> c_int;
    pub fn EVP_DigestVerifyInit(
        ctx: *mut EVP_MD_CTX,
        pctx: *mut *mut EVP_PKEY_CTX,
        type_: *const EVP_MD,
        e: *mut ENGINE,
        pkey: *mut EVP_PKEY,
    ) -> c_int;
    pub fn EVP_SealInit(
        ctx: *mut EVP_CIPHER_CTX,
        type_: *const EVP_CIPHER,
        ek: *mut *mut c_uchar,
        ekl: *mut c_int,
        iv: *mut c_uchar,
        pubk: *mut *mut EVP_PKEY,
        npubk: c_int,
    ) -> c_int;
    pub fn EVP_SealFinal(ctx: *mut EVP_CIPHER_CTX, out: *mut c_uchar, outl: *mut c_int) -> c_int;
    pub fn EVP_EncryptInit_ex(
        ctx: *mut EVP_CIPHER_CTX,
        cipher: *const EVP_CIPHER,
        impl_: *mut ENGINE,
        key: *const c_uchar,
        iv: *const c_uchar,
    ) -> c_int;
    pub fn EVP_EncryptUpdate(
        ctx: *mut EVP_CIPHER_CTX,
        out: *mut c_uchar,
        outl: *mut c_int,
        in_: *const u8,
        inl: c_int,
    ) -> c_int;
    pub fn EVP_EncryptFinal_ex(
        ctx: *mut EVP_CIPHER_CTX,
        out: *mut c_uchar,
        outl: *mut c_int,
    ) -> c_int;
    pub fn EVP_OpenInit(
        ctx: *mut EVP_CIPHER_CTX,
        type_: *const EVP_CIPHER,
        ek: *const c_uchar,
        ekl: c_int,
        iv: *const c_uchar,
        priv_: *mut EVP_PKEY,
    ) -> c_int;
    pub fn EVP_OpenFinal(ctx: *mut EVP_CIPHER_CTX, out: *mut c_uchar, outl: *mut c_int) -> c_int;
    pub fn EVP_DecryptInit_ex(
        ctx: *mut EVP_CIPHER_CTX,
        cipher: *const EVP_CIPHER,
        impl_: *mut ENGINE,
        key: *const c_uchar,
        iv: *const c_uchar,
    ) -> c_int;
    pub fn EVP_DecryptUpdate(
        ctx: *mut EVP_CIPHER_CTX,
        out: *mut c_uchar,
        outl: *mut c_int,
        in_: *const u8,
        inl: c_int,
    ) -> c_int;
    pub fn EVP_DecryptFinal_ex(
        ctx: *mut EVP_CIPHER_CTX,
        outm: *mut c_uchar,
        outl: *mut c_int,
    ) -> c_int;
}
cfg_if! {
    if #[cfg(ossl300)] {
        extern "C" {
            pub fn EVP_PKEY_get_size(pkey: *const EVP_PKEY) -> c_int;
        }

        #[inline]
        pub unsafe fn EVP_PKEY_size(pkey: *const EVP_PKEY) -> c_int {
            EVP_PKEY_get_size(pkey)
        }
    } else {
        const_ptr_api! {
            extern "C" {
                pub fn EVP_PKEY_size(pkey: #[const_ptr_if(any(ossl111b, libressl280))] EVP_PKEY) -> c_int;
            }
        }
    }
}
cfg_if! {
    if #[cfg(ossl111)] {
        extern "C" {
            pub fn EVP_DigestSign(
                ctx: *mut EVP_MD_CTX,
                sigret: *mut c_uchar,
                siglen: *mut size_t,
                tbs: *const c_uchar,
                tbslen: size_t
            ) -> c_int;

            pub fn EVP_DigestVerify(
                ctx: *mut EVP_MD_CTX,
                sigret: *const c_uchar,
                siglen: size_t,
                tbs: *const c_uchar,
                tbslen: size_t
            ) -> c_int;
        }
    }
}
const_ptr_api! {
    extern "C" {
        pub fn EVP_DigestVerifyFinal(
            ctx: *mut EVP_MD_CTX,
            sigret: #[const_ptr_if(any(ossl102, libressl280))] c_uchar,
            siglen: size_t,
        ) -> c_int;
    }
}

extern "C" {
    pub fn EVP_CIPHER_CTX_new() -> *mut EVP_CIPHER_CTX;
    pub fn EVP_CIPHER_CTX_free(ctx: *mut EVP_CIPHER_CTX);
    pub fn EVP_MD_CTX_copy_ex(dst: *mut EVP_MD_CTX, src: *const EVP_MD_CTX) -> c_int;
    pub fn EVP_CIPHER_CTX_set_key_length(ctx: *mut EVP_CIPHER_CTX, keylen: c_int) -> c_int;
    pub fn EVP_CIPHER_CTX_set_padding(ctx: *mut EVP_CIPHER_CTX, padding: c_int) -> c_int;
    pub fn EVP_CIPHER_CTX_ctrl(
        ctx: *mut EVP_CIPHER_CTX,
        type_: c_int,
        arg: c_int,
        ptr: *mut c_void,
    ) -> c_int;

    pub fn EVP_md_null() -> *const EVP_MD;
    pub fn EVP_md5() -> *const EVP_MD;
    pub fn EVP_sha1() -> *const EVP_MD;
    pub fn EVP_sha224() -> *const EVP_MD;
    pub fn EVP_sha256() -> *const EVP_MD;
    pub fn EVP_sha384() -> *const EVP_MD;
    pub fn EVP_sha512() -> *const EVP_MD;
    #[cfg(ossl111)]
    pub fn EVP_sha3_224() -> *const EVP_MD;
    #[cfg(ossl111)]
    pub fn EVP_sha3_256() -> *const EVP_MD;
    #[cfg(ossl111)]
    pub fn EVP_sha3_384() -> *const EVP_MD;
    #[cfg(ossl111)]
    pub fn EVP_sha3_512() -> *const EVP_MD;
    #[cfg(ossl111)]
    pub fn EVP_shake128() -> *const EVP_MD;
    #[cfg(ossl111)]
    pub fn EVP_shake256() -> *const EVP_MD;
    pub fn EVP_ripemd160() -> *const EVP_MD;
    #[cfg(all(any(ossl111, libressl291), not(osslconf = "OPENSSL_NO_SM3")))]
    pub fn EVP_sm3() -> *const EVP_MD;
    pub fn EVP_des_ecb() -> *const EVP_CIPHER;
    pub fn EVP_des_ede3() -> *const EVP_CIPHER;
    pub fn EVP_des_ede3_cbc() -> *const EVP_CIPHER;
    pub fn EVP_des_ede3_cfb64() -> *const EVP_CIPHER;
    pub fn EVP_des_cbc() -> *const EVP_CIPHER;
    pub fn EVP_rc4() -> *const EVP_CIPHER;
    pub fn EVP_bf_ecb() -> *const EVP_CIPHER;
    pub fn EVP_bf_cbc() -> *const EVP_CIPHER;
    pub fn EVP_bf_cfb64() -> *const EVP_CIPHER;
    pub fn EVP_bf_ofb() -> *const EVP_CIPHER;
    pub fn EVP_aes_128_ecb() -> *const EVP_CIPHER;
    pub fn EVP_aes_128_cbc() -> *const EVP_CIPHER;
    pub fn EVP_aes_128_cfb1() -> *const EVP_CIPHER;
    pub fn EVP_aes_128_cfb8() -> *const EVP_CIPHER;
    pub fn EVP_aes_128_cfb128() -> *const EVP_CIPHER;
    pub fn EVP_aes_128_ctr() -> *const EVP_CIPHER;
    pub fn EVP_aes_128_ccm() -> *const EVP_CIPHER;
    pub fn EVP_aes_128_gcm() -> *const EVP_CIPHER;
    pub fn EVP_aes_128_xts() -> *const EVP_CIPHER;
    pub fn EVP_aes_128_ofb() -> *const EVP_CIPHER;
    #[cfg(ossl110)]
    pub fn EVP_aes_128_ocb() -> *const EVP_CIPHER;
    pub fn EVP_aes_192_ecb() -> *const EVP_CIPHER;
    pub fn EVP_aes_192_cbc() -> *const EVP_CIPHER;
    pub fn EVP_aes_192_cfb1() -> *const EVP_CIPHER;
    pub fn EVP_aes_192_cfb8() -> *const EVP_CIPHER;
    pub fn EVP_aes_192_cfb128() -> *const EVP_CIPHER;
    pub fn EVP_aes_192_ctr() -> *const EVP_CIPHER;
    pub fn EVP_aes_192_ccm() -> *const EVP_CIPHER;
    pub fn EVP_aes_192_gcm() -> *const EVP_CIPHER;
    pub fn EVP_aes_192_ofb() -> *const EVP_CIPHER;
    #[cfg(ossl110)]
    pub fn EVP_aes_192_ocb() -> *const EVP_CIPHER;
    pub fn EVP_aes_256_ecb() -> *const EVP_CIPHER;
    pub fn EVP_aes_256_cbc() -> *const EVP_CIPHER;
    pub fn EVP_aes_256_cfb1() -> *const EVP_CIPHER;
    pub fn EVP_aes_256_cfb8() -> *const EVP_CIPHER;
    pub fn EVP_aes_256_cfb128() -> *const EVP_CIPHER;
    pub fn EVP_aes_256_ctr() -> *const EVP_CIPHER;
    pub fn EVP_aes_256_ccm() -> *const EVP_CIPHER;
    pub fn EVP_aes_256_gcm() -> *const EVP_CIPHER;
    pub fn EVP_aes_256_xts() -> *const EVP_CIPHER;
    pub fn EVP_aes_256_ofb() -> *const EVP_CIPHER;
    #[cfg(ossl110)]
    pub fn EVP_aes_256_ocb() -> *const EVP_CIPHER;
    #[cfg(all(ossl110, not(osslconf = "OPENSSL_NO_CHACHA")))]
    pub fn EVP_chacha20() -> *const ::EVP_CIPHER;
    #[cfg(all(ossl110, not(osslconf = "OPENSSL_NO_CHACHA")))]
    pub fn EVP_chacha20_poly1305() -> *const ::EVP_CIPHER;
    #[cfg(not(osslconf = "OPENSSL_NO_SEED"))]
    pub fn EVP_seed_cbc() -> *const EVP_CIPHER;
    #[cfg(not(osslconf = "OPENSSL_NO_SEED"))]
    pub fn EVP_seed_cfb128() -> *const EVP_CIPHER;
    #[cfg(not(osslconf = "OPENSSL_NO_SEED"))]
    pub fn EVP_seed_ecb() -> *const EVP_CIPHER;
    #[cfg(not(osslconf = "OPENSSL_NO_SEED"))]
    pub fn EVP_seed_ofb() -> *const EVP_CIPHER;

    #[cfg(not(ossl110))]
    pub fn OPENSSL_add_all_algorithms_noconf();

    pub fn EVP_get_digestbyname(name: *const c_char) -> *const EVP_MD;
    pub fn EVP_get_cipherbyname(name: *const c_char) -> *const EVP_CIPHER;
}

cfg_if! {
    if #[cfg(ossl300)] {
        extern "C" {
            pub fn EVP_PKEY_get_id(pkey: *const EVP_PKEY) -> c_int;
            pub fn EVP_PKEY_get_bits(key: *const EVP_PKEY) -> c_int;
        }

        #[inline]
        pub unsafe fn EVP_PKEY_id(pkey: *const EVP_PKEY) -> c_int {
            EVP_PKEY_get_id(pkey)
        }

        #[inline]
        pub unsafe fn EVP_PKEY_bits(pkey: *const EVP_PKEY) -> c_int {
            EVP_PKEY_get_bits(pkey)
        }
    } else {
        extern "C" {
            pub fn EVP_PKEY_id(pkey: *const EVP_PKEY) -> c_int;
        }
        const_ptr_api! {
            extern "C" {
                pub fn EVP_PKEY_bits(key: #[const_ptr_if(any(ossl110, libressl280))] EVP_PKEY) -> c_int;
            }
        }
    }
}
extern "C" {
    pub fn EVP_PKEY_assign(pkey: *mut EVP_PKEY, typ: c_int, key: *mut c_void) -> c_int;

    pub fn EVP_PKEY_set1_RSA(k: *mut EVP_PKEY, r: *mut RSA) -> c_int;
    pub fn EVP_PKEY_get1_RSA(k: *mut EVP_PKEY) -> *mut RSA;
    pub fn EVP_PKEY_get1_DSA(k: *mut EVP_PKEY) -> *mut DSA;
    pub fn EVP_PKEY_get1_DH(k: *mut EVP_PKEY) -> *mut DH;
    pub fn EVP_PKEY_get1_EC_KEY(k: *mut EVP_PKEY) -> *mut EC_KEY;

    pub fn EVP_PKEY_new() -> *mut EVP_PKEY;
    pub fn EVP_PKEY_free(k: *mut EVP_PKEY);
    #[cfg(any(ossl110, libressl270))]
    pub fn EVP_PKEY_up_ref(pkey: *mut EVP_PKEY) -> c_int;

    pub fn d2i_AutoPrivateKey(
        a: *mut *mut EVP_PKEY,
        pp: *mut *const c_uchar,
        length: c_long,
    ) -> *mut EVP_PKEY;

    pub fn EVP_PKEY_cmp(a: *const EVP_PKEY, b: *const EVP_PKEY) -> c_int;

    pub fn EVP_PKEY_copy_parameters(to: *mut EVP_PKEY, from: *const EVP_PKEY) -> c_int;

    pub fn PKCS5_PBKDF2_HMAC_SHA1(
        pass: *const c_char,
        passlen: c_int,
        salt: *const u8,
        saltlen: c_int,
        iter: c_int,
        keylen: c_int,
        out: *mut u8,
    ) -> c_int;
    pub fn PKCS5_PBKDF2_HMAC(
        pass: *const c_char,
        passlen: c_int,
        salt: *const c_uchar,
        saltlen: c_int,
        iter: c_int,
        digest: *const EVP_MD,
        keylen: c_int,
        out: *mut u8,
    ) -> c_int;

    #[cfg(ossl110)]
    pub fn EVP_PBE_scrypt(
        pass: *const c_char,
        passlen: size_t,
        salt: *const c_uchar,
        saltlen: size_t,
        N: u64,
        r: u64,
        p: u64,
        maxmem: u64,
        key: *mut c_uchar,
        keylen: size_t,
    ) -> c_int;
}

pub const EVP_PKEY_OP_KEYGEN: c_int = 1 << 2;
cfg_if! {
    if #[cfg(ossl300)] {
        pub const EVP_PKEY_OP_SIGN: c_int = 1 << 4;
        pub const EVP_PKEY_OP_VERIFY: c_int = 1 << 5;
        pub const EVP_PKEY_OP_VERIFYRECOVER: c_int = 1 << 6;
        pub const EVP_PKEY_OP_SIGNCTX: c_int = 1 << 7;
        pub const EVP_PKEY_OP_VERIFYCTX: c_int = 1 << 8;
        pub const EVP_PKEY_OP_ENCRYPT: c_int = 1 << 9;
        pub const EVP_PKEY_OP_DECRYPT: c_int = 1 << 10;
    } else {
        pub const EVP_PKEY_OP_SIGN: c_int = 1 << 3;
        pub const EVP_PKEY_OP_VERIFY: c_int = 1 << 4;
        pub const EVP_PKEY_OP_VERIFYRECOVER: c_int = 1 << 5;
        pub const EVP_PKEY_OP_SIGNCTX: c_int = 1 << 6;
        pub const EVP_PKEY_OP_VERIFYCTX: c_int = 1 << 7;
        pub const EVP_PKEY_OP_ENCRYPT: c_int = 1 << 8;
        pub const EVP_PKEY_OP_DECRYPT: c_int = 1 << 9;
    }
}

pub const EVP_PKEY_OP_TYPE_SIG: c_int = EVP_PKEY_OP_SIGN
    | EVP_PKEY_OP_VERIFY
    | EVP_PKEY_OP_VERIFYRECOVER
    | EVP_PKEY_OP_SIGNCTX
    | EVP_PKEY_OP_VERIFYCTX;

pub const EVP_PKEY_OP_TYPE_CRYPT: c_int = EVP_PKEY_OP_ENCRYPT | EVP_PKEY_OP_DECRYPT;

pub const EVP_PKEY_CTRL_SET_MAC_KEY: c_int = 6;

pub const EVP_PKEY_CTRL_CIPHER: c_int = 12;

pub const EVP_PKEY_ALG_CTRL: c_int = 0x1000;

extern "C" {
    pub fn EVP_PKEY_CTX_new(k: *mut EVP_PKEY, e: *mut ENGINE) -> *mut EVP_PKEY_CTX;
    pub fn EVP_PKEY_CTX_new_id(id: c_int, e: *mut ENGINE) -> *mut EVP_PKEY_CTX;
    pub fn EVP_PKEY_CTX_free(ctx: *mut EVP_PKEY_CTX);

    pub fn EVP_PKEY_CTX_ctrl(
        ctx: *mut EVP_PKEY_CTX,
        keytype: c_int,
        optype: c_int,
        cmd: c_int,
        p1: c_int,
        p2: *mut c_void,
    ) -> c_int;

    pub fn EVP_PKEY_CTX_ctrl_str(
        ctx: *mut EVP_PKEY_CTX,
        type_: *const c_char,
        value: *const c_char,
    ) -> c_int;

    pub fn EVP_PKEY_new_mac_key(
        type_: c_int,
        e: *mut ENGINE,
        key: *const c_uchar,
        keylen: c_int,
    ) -> *mut EVP_PKEY;

    pub fn EVP_PKEY_derive_init(ctx: *mut EVP_PKEY_CTX) -> c_int;
    pub fn EVP_PKEY_derive_set_peer(ctx: *mut EVP_PKEY_CTX, peer: *mut EVP_PKEY) -> c_int;
    pub fn EVP_PKEY_derive(ctx: *mut EVP_PKEY_CTX, key: *mut c_uchar, size: *mut size_t) -> c_int;

    #[cfg(ossl300)]
    pub fn EVP_PKEY_Q_keygen(
        libctx: *mut OSSL_LIB_CTX,
        propq: *const c_char,
        type_: *const c_char,
        ...
    ) -> *mut EVP_PKEY;
    pub fn EVP_PKEY_keygen_init(ctx: *mut EVP_PKEY_CTX) -> c_int;
    pub fn EVP_PKEY_keygen(ctx: *mut EVP_PKEY_CTX, key: *mut *mut EVP_PKEY) -> c_int;

    pub fn EVP_PKEY_encrypt_init(ctx: *mut EVP_PKEY_CTX) -> c_int;
    pub fn EVP_PKEY_encrypt(
        ctx: *mut EVP_PKEY_CTX,
        pout: *mut c_uchar,
        poutlen: *mut size_t,
        pin: *const c_uchar,
        pinlen: size_t,
    ) -> c_int;
    pub fn EVP_PKEY_decrypt_init(ctx: *mut EVP_PKEY_CTX) -> c_int;
    pub fn EVP_PKEY_decrypt(
        ctx: *mut EVP_PKEY_CTX,
        pout: *mut c_uchar,
        poutlen: *mut size_t,
        pin: *const c_uchar,
        pinlen: size_t,
    ) -> c_int;
}

const_ptr_api! {
    extern "C" {
        pub fn EVP_PKCS82PKEY(p8: #[const_ptr_if(any(ossl110, libressl280))] PKCS8_PRIV_KEY_INFO) -> *mut EVP_PKEY;
    }
}

cfg_if! {
    if #[cfg(any(ossl111))] {
        extern "C" {
            pub fn EVP_PKEY_get_raw_public_key(
                pkey: *const EVP_PKEY,
                ppub: *mut c_uchar,
                len: *mut size_t,
            ) -> c_int;
            pub fn EVP_PKEY_new_raw_public_key(
                ttype: c_int,
                e: *mut ENGINE,
                key: *const c_uchar,
                keylen: size_t,
            ) -> *mut EVP_PKEY;
            pub fn EVP_PKEY_get_raw_private_key(
                pkey: *const EVP_PKEY,
                ppriv: *mut c_uchar,
                len: *mut size_t,
            ) -> c_int;
            pub fn EVP_PKEY_new_raw_private_key(
                ttype: c_int,
                e: *mut ENGINE,
                key: *const c_uchar,
                keylen: size_t,
            ) -> *mut EVP_PKEY;
        }
    }
}

extern "C" {
    pub fn EVP_EncodeBlock(dst: *mut c_uchar, src: *const c_uchar, src_len: c_int) -> c_int;
    pub fn EVP_DecodeBlock(dst: *mut c_uchar, src: *const c_uchar, src_len: c_int) -> c_int;
}
