package ms.rohde.openpgpicsfpoc.core.domain;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import ms.rohde.hexagonalarch.annotations.DomainService;

/**
 * Berechnet den Digest einer Nachricht lokal (kein Geheimnis involviert,
 * daher keine HSM-Operation). Nur der anschliessende Signaturschritt ueber
 * diesen Digest erfolgt via {@code HsmSignature}.
 *
 * <p>Fuer alle Signaturalgorithmen dieser PoC wird einheitlich SHA-256
 * verwendet. Bei EdDSA (Ed25519) weicht das vom ueblichen "pure EdDSA"-Schema
 * ab, das direkt ueber die Nachricht signiert statt ueber einen vorab
 * berechneten Digest - das ist eine bewusste Vereinfachung dieser PoC, siehe
 * JavaDoc auf {@code HsmSignatureRequest}.</p>
 */
@DomainService
public final class MessageDigestCalculator {

    private static final String ALGORITHM = "SHA-256";

    public MessageDigestCalculator() {}

    public ByteSequence sha256(ByteSequence message) {
        try {
            MessageDigest digest = MessageDigest.getInstance(ALGORITHM);
            return ByteSequence.of(digest.digest(message.value()));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(ALGORITHM + " ist auf dieser JVM nicht verfuegbar", e);
        }
    }
}
