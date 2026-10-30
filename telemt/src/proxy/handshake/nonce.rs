use super::*;

pub fn generate_tg_nonce(
    proto_tag: ProtoTag,
    dc_idx: i16,
    client_enc_key: &[u8; 32],
    client_enc_iv: u128,
    rng: &SecureRandom,
    fast_mode: bool,
) -> ([u8; HANDSHAKE_LEN], [u8; 32], u128, [u8; 32], u128) {
    loop {
        let bytes = rng.bytes(HANDSHAKE_LEN);
        let Ok(mut nonce): Result<[u8; HANDSHAKE_LEN], _> = bytes.try_into() else {
            continue;
        };

        if RESERVED_NONCE_FIRST_BYTES.contains(&nonce[0]) {
            continue;
        }

        let first_four: [u8; 4] = [nonce[0], nonce[1], nonce[2], nonce[3]];
        if RESERVED_NONCE_BEGINNINGS.contains(&first_four) {
            continue;
        }

        let continue_four: [u8; 4] = [nonce[4], nonce[5], nonce[6], nonce[7]];
        if RESERVED_NONCE_CONTINUES.contains(&continue_four) {
            continue;
        }

        nonce[PROTO_TAG_POS..PROTO_TAG_POS + 4].copy_from_slice(&proto_tag.to_bytes());
        // CRITICAL: write dc_idx so upstream DC knows where to route
        nonce[DC_IDX_POS..DC_IDX_POS + 2].copy_from_slice(&dc_idx.to_le_bytes());

        if fast_mode {
            let mut key_iv = Zeroizing::new(Vec::with_capacity(KEY_LEN + IV_LEN));
            key_iv.extend_from_slice(client_enc_key);
            key_iv.extend_from_slice(&client_enc_iv.to_be_bytes());
            // Python/C compatibility requires reversed enc_key+enc_iv nonce bytes.
            key_iv.reverse();
            nonce[SKIP_LEN..SKIP_LEN + KEY_LEN + IV_LEN].copy_from_slice(&key_iv);
        }

        let enc_key_iv = &nonce[SKIP_LEN..SKIP_LEN + KEY_LEN + IV_LEN];
        let dec_key_iv = Zeroizing::new(enc_key_iv.iter().rev().copied().collect::<Vec<u8>>());

        let mut tg_enc_key = [0u8; 32];
        tg_enc_key.copy_from_slice(&enc_key_iv[..KEY_LEN]);
        let mut tg_enc_iv_arr = [0u8; IV_LEN];
        tg_enc_iv_arr.copy_from_slice(&enc_key_iv[KEY_LEN..]);
        let tg_enc_iv = u128::from_be_bytes(tg_enc_iv_arr);

        let mut tg_dec_key = [0u8; 32];
        tg_dec_key.copy_from_slice(&dec_key_iv[..KEY_LEN]);
        let mut tg_dec_iv_arr = [0u8; IV_LEN];
        tg_dec_iv_arr.copy_from_slice(&dec_key_iv[KEY_LEN..]);
        let tg_dec_iv = u128::from_be_bytes(tg_dec_iv_arr);

        return (nonce, tg_enc_key, tg_enc_iv, tg_dec_key, tg_dec_iv);
    }
}

/// Encrypt nonce for sending to Telegram and return cipher objects with correct counter state
pub fn encrypt_tg_nonce_with_ciphers(nonce: &[u8; HANDSHAKE_LEN]) -> (Vec<u8>, AesCtr, AesCtr) {
    let enc_key_iv = &nonce[SKIP_LEN..SKIP_LEN + KEY_LEN + IV_LEN];
    let dec_key_iv = Zeroizing::new(enc_key_iv.iter().rev().copied().collect::<Vec<u8>>());

    let mut enc_key = [0u8; 32];
    enc_key.copy_from_slice(&enc_key_iv[..KEY_LEN]);
    let mut enc_iv_arr = [0u8; IV_LEN];
    enc_iv_arr.copy_from_slice(&enc_key_iv[KEY_LEN..]);
    let enc_iv = u128::from_be_bytes(enc_iv_arr);

    let mut dec_key = [0u8; 32];
    dec_key.copy_from_slice(&dec_key_iv[..KEY_LEN]);
    let mut dec_iv_arr = [0u8; IV_LEN];
    dec_iv_arr.copy_from_slice(&dec_key_iv[KEY_LEN..]);
    let dec_iv = u128::from_be_bytes(dec_iv_arr);

    let mut encryptor = AesCtr::new(&enc_key, enc_iv);
    // Encryption advances the nonce counter from zero to four.
    let encrypted_full = encryptor.encrypt(nonce);

    let mut result = nonce[..PROTO_TAG_POS].to_vec();
    result.extend_from_slice(&encrypted_full[PROTO_TAG_POS..]);

    let decryptor = AesCtr::new(&dec_key, dec_iv);
    enc_key.zeroize();
    dec_key.zeroize();

    (result, encryptor, decryptor)
}

/// Encrypt nonce for sending to Telegram (legacy function for compatibility)
pub fn encrypt_tg_nonce(nonce: &[u8; HANDSHAKE_LEN]) -> Vec<u8> {
    let (encrypted, _, _) = encrypt_tg_nonce_with_ciphers(nonce);
    encrypted
}
