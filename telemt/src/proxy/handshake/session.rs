use super::*;

/// Result of successful handshake
///
/// Key material (`dec_key`, `dec_iv`, `enc_key`, `enc_iv`) is
/// zeroized on drop.
#[derive(Debug)]
pub struct HandshakeSuccess {
    /// Authenticated user name
    pub user: String,
    /// Target datacenter index
    pub dc_idx: i16,
    /// Protocol variant (abridged/intermediate/secure)
    pub proto_tag: ProtoTag,
    /// Decryption key and IV (for reading from client)
    pub dec_key: [u8; 32],
    pub dec_iv: u128,
    /// Encryption key and IV (for writing to client)
    pub enc_key: [u8; 32],
    pub enc_iv: u128,
    /// Client address
    pub peer: SocketAddr,
    /// Whether TLS was used
    pub is_tls: bool,
}

impl Drop for HandshakeSuccess {
    fn drop(&mut self) {
        self.dec_key.zeroize();
        self.dec_iv.zeroize();
        self.enc_key.zeroize();
        self.enc_iv.zeroize();
    }
}
