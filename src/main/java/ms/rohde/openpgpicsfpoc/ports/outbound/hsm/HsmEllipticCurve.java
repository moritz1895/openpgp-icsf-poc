package ms.rohde.openpgpicsfpoc.ports.outbound.hsm;

/**
 * Von der {@link HsmKeyAgreement}-Primitive unterstuetzte Kurven.
 * {@link #X25519} ist nativ in RFC 9580, {@link #P256}/{@link #P384} decken
 * das klassische ECDH-Fallback-Profil nach RFC 6637 ab (siehe
 * CCA-Realitaetscheck im Projektplan zur unsicheren X25519-Unterstuetzung
 * auf realer CCA-Hardware).
 */
public enum HsmEllipticCurve {
    X25519,
    P256,
    P384
}
