use syft_crypto_protocol::{decrypt_message, encrypt_message, encryption::EncryptionRecipient};
use syftbox_sdk::{parse_envelope, SyftRecoveryKey};

#[test]
fn multi_recipient_encrypt_decrypt_round_trip() {
    let mut rng = rand::rng();

    let sender_keys = SyftRecoveryKey::generate()
        .derive_keys()
        .expect("sender key derivation");
    let recipient1_keys = SyftRecoveryKey::generate()
        .derive_keys()
        .expect("recipient1 key derivation");
    let recipient2_keys = SyftRecoveryKey::generate()
        .derive_keys()
        .expect("recipient2 key derivation");

    let sender_bundle = sender_keys
        .to_public_bundle(&mut rng)
        .expect("sender bundle");
    let recipient1_bundle = recipient1_keys
        .to_public_bundle(&mut rng)
        .expect("recipient1 bundle");
    let recipient2_bundle = recipient2_keys
        .to_public_bundle(&mut rng)
        .expect("recipient2 bundle");

    let plaintext = b"multi-recipient payload";
    let envelope = encrypt_message(
        "alice@example.org",
        &sender_keys,
        &[
            EncryptionRecipient {
                identity: "bob@example.org",
                bundle: &recipient1_bundle,
            },
            EncryptionRecipient {
                identity: "carol@example.org",
                bundle: &recipient2_bundle,
            },
        ],
        plaintext,
        Some("payload.bin"),
        &mut rng,
    )
    .expect("encrypt for multiple recipients");

    let parsed = parse_envelope(&envelope).expect("parse envelope");

    let decrypted_bob =
        decrypt_message("bob@example.org", &recipient1_keys, &sender_bundle, &parsed)
            .expect("bob decrypt");
    assert_eq!(decrypted_bob, plaintext);

    let decrypted_carol = decrypt_message(
        "carol@example.org",
        &recipient2_keys,
        &sender_bundle,
        &parsed,
    )
    .expect("carol decrypt");
    assert_eq!(decrypted_carol, plaintext);
}
