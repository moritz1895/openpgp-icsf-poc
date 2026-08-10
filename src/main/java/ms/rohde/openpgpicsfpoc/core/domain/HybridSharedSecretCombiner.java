package ms.rohde.openpgpicsfpoc.core.domain;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import ms.rohde.hexagonalarch.annotations.DomainService;

/**
 * Kombiniert die beiden Shared Secrets eines PQ/T-Hybridverfahrens
 * (klassisches ECDH-Shared-Secret und ML-KEM-Shared-Secret) lokal zu einem
 * gemeinsamen Sitzungsschluessel-Material.
 *
 * <p>Laut Projektplan ist dieses Kombinieren ein unkritischer, lokaler
 * Schritt (Standardvorgehen bei PQ/T-Hybriden) und erfordert keine
 * HSM-Operation. Diese PoC verwendet dafuer vereinfachend
 * SHA-256(klassisch || postquantum) statt einer RFC-9580-exakten KDF - die
 * exakte Parametrisierung ist Sache der spaeteren OpenPGP-Paket-Framing-
 * Implementierung (Bouncy-Castle-Bridge).</p>
 */
@DomainService
public final class HybridSharedSecretCombiner {

    private static final String ALGORITHM = "SHA-256";

    public HybridSharedSecretCombiner() {}

    public ByteSequence combine(ByteSequence classicalSharedSecret, ByteSequence postQuantumSharedSecret) {
        try {
            MessageDigest digest = MessageDigest.getInstance(ALGORITHM);
            digest.update(classicalSharedSecret.value());
            digest.update(postQuantumSharedSecret.value());
            return ByteSequence.of(digest.digest());
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(ALGORITHM + " ist auf dieser JVM nicht verfuegbar", e);
        }
    }
}
