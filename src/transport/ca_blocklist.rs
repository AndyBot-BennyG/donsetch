//! Certificate-authority keys refused in any TLS chain, whatever the
//! trust store says.

use boring::x509::X509Ref;

/// SHA-256 of the DER SubjectPublicKeyInfo of every blocked CA key.
pub(crate) const COMPROMISED_CA_KEYS: &[[u8; 32]] = &[
    // Adding a key here: also bump VERSION in routes.rs. Saved h3 sessions
    // resume without verifying the certificate again, so a session from a
    // chain through the new key would keep working until it expires.
    //
    // eMudhra, October 2026: the private keys can be recovered from the
    // certificates themselves (https://emudhra.we-have-a-problem.com/).
    // Each key has two certificates: one under its emSign G3 root and a
    // Sectigo cross-sign under AAA Certificate Services. Matching the key
    // covers both, and any reissue of it.
    hex32("EBED6475C2C2D80FCB199F3FE8DD6E6B3CE60B77EB15D4E42C3DEC0C6F5B5105"), // EM DV TLS CA - G3B
    hex32("49DD353DC2B919A3770645117D0E60C16115E7D1BC259EEFE734B00EA434FE5F"), // EM DV TLS CA - G3C
    hex32("43BFFA19D6EF651451F6841E019931E96F6F2EAEFF28AB4B6F1CE4576DE2717B"), // EM OV TLS CA - G3B
    hex32("63ECEFEE431D49523BC1136C4E72D0206A477086CAF606CD5CF025686C109CF8"), // EM OV TLS CA - G3C
    hex32("E0254C7FCDC265E2F0F8A428DABB75AB4AE039B4872D62F5EE57F0877D5A8A41"), // EM EV TLS CA - G3B
    hex32("5C0660A2B164910D8FF589C18E14552E9E0EC237DCEFE2CB736D41A4811F81A0"), // EM EV TLS CA - G3C
    hex32("EC4FFA1AD0AC88081314B7AAFFEF6A91F97CD57291BB5BA686C5415F5EB4F6B6"), // EM OV CS CA - G3B
    hex32("92C063D67E8F14DB71D288E11266FFDAF69CBF115F7BAB14F3BC2F68D25E0E30"), // EM OV CS CA - G3C
];

/// True when the SHA-256 of `cert`'s DER SubjectPublicKeyInfo is one of
/// `keys`. A public key that cannot be encoded is never blocked.
pub(crate) fn is_blocked(cert: &X509Ref, keys: &[[u8; 32]]) -> bool {
    // An undecodable key is no gap: as an issuer it cannot verify the
    // signature below it, and as a leaf it cannot sign the handshake.
    let Ok(spki) = cert.public_key().and_then(|key| key.public_key_to_der()) else {
        return false;
    };
    keys.contains(&boring::sha::sha256(&spki))
}

const fn hex32(hex: &str) -> [u8; 32] {
    const fn nibble(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'A'..=b'F' => c - b'A' + 10,
            _ => panic!("blocklist hashes are uppercase hex"),
        }
    }
    let hex = hex.as_bytes();
    assert!(hex.len() == 64, "a SHA-256 is 64 hex digits");
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = (nibble(hex[2 * i]) << 4) | nibble(hex[2 * i + 1]);
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use boring::x509::X509;

    fn spki_sha256(cert: &X509Ref) -> [u8; 32] {
        boring::sha::sha256(&cert.public_key().unwrap().public_key_to_der().unwrap())
    }

    // Every published certificate is blocked, and every list entry is
    // hit by one of them: a mistyped hash fails here instead of silently
    // blocking nothing.
    #[test]
    fn every_compromised_emudhra_certificate_is_blocked() {
        let certs = X509::stack_from_pem(include_bytes!(
            "../../tests/landmarks/emudhra-compromised-cas.pem"
        ))
        .unwrap();
        assert_eq!(certs.len(), 16);
        for cert in &certs {
            assert!(
                is_blocked(cert, COMPROMISED_CA_KEYS),
                "{:?} is not blocked",
                cert.subject_name()
            );
        }
        for key in COMPROMISED_CA_KEYS {
            assert!(
                certs.iter().any(|cert| spki_sha256(cert) == *key),
                "list entry {key:02X?} matches no published certificate"
            );
        }
    }

    #[test]
    fn an_unrelated_key_is_not_blocked() {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert = X509::from_der(cert.cert.der()).unwrap();
        assert!(!is_blocked(&cert, COMPROMISED_CA_KEYS));
        assert!(is_blocked(&cert, &[spki_sha256(&cert)]));
    }

    #[test]
    fn hex32_decodes_uppercase_hex() {
        let key = hex32("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1EFF");
        assert_eq!(key[..3], [0x00, 0x01, 0x02]);
        assert_eq!(key[10], 0x0A);
        assert_eq!(key[31], 0xFF);
    }
}
