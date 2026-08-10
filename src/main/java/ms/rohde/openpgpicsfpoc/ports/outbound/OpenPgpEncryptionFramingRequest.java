package ms.rohde.openpgpicsfpoc.ports.outbound;

import java.util.Objects;
import ms.rohde.openpgpicsfpoc.core.domain.ByteSequence;
import ms.rohde.openpgpicsfpoc.core.domain.PgpEncryptionProfile;
import ms.rohde.openpgpicsfpoc.core.domain.PgpKeyReference;
import ms.rohde.openpgpicsfpoc.core.domain.PgpPublicKeyAlgorithm;
import org.jspecify.annotations.Nullable;

/**
 * Traegt die bereits ueber die Hsm-Primitiven berechneten kryptographischen
 * Artefakte (verpackter Sitzungsschluessel bzw. Shared-Secret-Ableitungen,
 * Chiffretext, ggf. Authentisierungs-Tag) sowie die zur Paketkodierung
 * benoetigten Metadaten an {@link OpenPgpMessageCodec#frameEncryptedMessage(OpenPgpEncryptionFramingRequest)}.
 *
 * <p>Welche der optionalen Felder ({@code wrappedSessionKey} fuer RSA,
 * {@code encapsulatedKey} zusaetzlich fuer das komposite PQC-Verfahren)
 * belegt sind, haengt von {@code algorithm} ab. Diese Aufteilung - Hsm-
 * Operationen in der Anwendungsschicht, reines Paket-Framing im spaeteren
 * Bouncy-Castle-Bridge-Adapter - ist eine bewusste Modellierungsentscheidung
 * dieser Iteration und kann sich anpassen, sobald der Bridge-Adapter
 * tatsaechlich implementiert wird.</p>
 */
public record OpenPgpEncryptionFramingRequest(
        PgpEncryptionProfile profile,
        PgpPublicKeyAlgorithm algorithm,
        PgpKeyReference recipient,
        @Nullable PgpKeyReference senderKeyAgreementKey,
        @Nullable ByteSequence wrappedSessionKey,
        @Nullable ByteSequence encapsulatedKey,
        ByteSequence ciphertext,
        @Nullable ByteSequence initializationVector,
        @Nullable ByteSequence authenticationTag) {

    public OpenPgpEncryptionFramingRequest {
        Objects.requireNonNull(profile, "profile darf nicht null sein");
        Objects.requireNonNull(algorithm, "algorithm darf nicht null sein");
        Objects.requireNonNull(recipient, "recipient darf nicht null sein");
        Objects.requireNonNull(ciphertext, "ciphertext darf nicht null sein");
    }
}
