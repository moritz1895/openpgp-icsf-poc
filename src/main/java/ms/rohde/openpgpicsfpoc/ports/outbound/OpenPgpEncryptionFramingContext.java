package ms.rohde.openpgpicsfpoc.ports.outbound;

import java.util.Objects;
import ms.rohde.openpgpicsfpoc.core.domain.ByteSequence;
import ms.rohde.openpgpicsfpoc.core.domain.HsmKeyHandle;
import ms.rohde.openpgpicsfpoc.core.domain.PgpPublicKeyAlgorithm;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmAesCipherMode;
import org.jspecify.annotations.Nullable;

/**
 * Ergebnis des Parsens einer verschluesselten OpenPGP-Nachricht durch
 * {@link OpenPgpMessageCodec#parseEncryptedMessage(ms.rohde.openpgpicsfpoc.core.domain.OpenPgpMessage)}:
 * die zur Entschluesselung benoetigten, aus dem Paketformat extrahierten
 * kryptographischen Parameter. Die Anwendungsschicht fuehrt darauf
 * aufbauend die eigentlichen Hsm-Operationen aus.
 */
public record OpenPgpEncryptionFramingContext(
        PgpPublicKeyAlgorithm algorithm,
        HsmAesCipherMode cipherMode,
        @Nullable ByteSequence wrappedSessionKey,
        @Nullable HsmKeyHandle senderKeyAgreementKeyHandle,
        @Nullable ByteSequence encapsulatedKey,
        ByteSequence ciphertext,
        @Nullable ByteSequence initializationVector,
        @Nullable ByteSequence authenticationTag) {

    public OpenPgpEncryptionFramingContext {
        Objects.requireNonNull(algorithm, "algorithm darf nicht null sein");
        Objects.requireNonNull(cipherMode, "cipherMode darf nicht null sein");
        Objects.requireNonNull(ciphertext, "ciphertext darf nicht null sein");
    }
}
