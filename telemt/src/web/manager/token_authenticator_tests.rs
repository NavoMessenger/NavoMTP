use super::*;

fn authenticator(key: u8) -> TokenAuthenticator {
    TokenAuthenticator {
        key: Zeroizing::new([key; 32]),
    }
}

#[test]
fn process_tokens_are_domain_separated_and_fail_closed_after_mutation() {
    let issuer = authenticator(0x11);
    let other_process = authenticator(0x22);
    let nonce = [0x33; TOKEN_NONCE_BYTES];
    let bootstrap = issuer.issue(TokenKind::Bootstrap, nonce);
    let session = issuer.issue(TokenKind::Session, nonce);

    assert_ne!(bootstrap, session);
    assert!(issuer.authentic(&bootstrap));
    assert!(issuer.authentic(&session));
    assert!(!other_process.authentic(&bootstrap));
    assert!(!other_process.authentic(&session));

    for token in [bootstrap, session] {
        for index in 0..TOKEN_BYTES {
            let mut mutated = token;
            mutated[index] ^= 1;
            assert!(!issuer.authentic(&mutated), "mutation at byte {index}");
        }
    }
}
