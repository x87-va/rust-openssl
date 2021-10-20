use crate::cvt_p;

foreign_type_and_impl_send_sync! {
    type CType = ffi::X509_CRL;
    fn drop = ffi::X509_CRL_free;

    /// A public or private key context.
    pub struct X509CRL;
    /// Reference to `X509CRL`.
    pub struct X509CRLRef;
}

impl X509CRL {
    from_pem! {
        /// Deserializes a PEM-encoded CRL structure.
        ///
        /// The input should have a header of `-----BEGIN CRL-----`.
        ///
        /// This corresponds to [`PEM_read_bio_X509_CRL`].
        ///
        /// [`PEM_read_bio_X509_CRL`]: https://www.openssl.org/docs/man1.0.2/crypto/PEM_read_bio_X509_CRL.html
        from_pem,
        X509CRL,
        ffi::PEM_read_bio_X509_CRL
    }

    from_der! {
        /// Deserializes a DER-encoded CRL structure.
        ///
        /// This corresponds to [`d2i_X509_CRL`].
        ///
        /// [`d2i_X509_CRL`]: https://www.openssl.org/docs/manmaster/man3/d2i_X509_CRL.html
        from_der,
        X509CRL,
        ffi::d2i_X509_CRL
    }
}
