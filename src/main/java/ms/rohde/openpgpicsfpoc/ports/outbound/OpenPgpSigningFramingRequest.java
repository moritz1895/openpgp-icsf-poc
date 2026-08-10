package ms.rohde.openpgpicsfpoc.ports.outbound;

import java.util.Objects;
import ms.rohde.openpgpicsfpoc.core.domain.ByteSequence;
import ms.rohde.openpgpicsfpoc.core.domain.PgpKeyReference;
import ms.rohde.openpgpicsfpoc.core.domain.PgpPublicKeyAlgorithm;

/**
 * Traegt die bereits per {@code HsmSignature} berechnete Signatur sowie die
 * zur Paketkodierung benoetigten Metadaten an
 * {@link OpenPgpMessageCodec#frameSignedMessage(OpenPgpSigningFramingRequest)}.
 */
public record OpenPgpSigningFramingRequest(
        ByteSequence message,
        PgpPublicKeyAlgorithm algorithm,
        PgpKeyReference signer,
        ByteSequence digest,
        ByteSequence signature) {

    public OpenPgpSigningFramingRequest {
        Objects.requireNonNull(message, "message darf nicht null sein");
        Objects.requireNonNull(algorithm, "algorithm darf nicht null sein");
        Objects.requireNonNull(signer, "signer darf nicht null sein");
        Objects.requireNonNull(digest, "digest darf nicht null sein");
        Objects.requireNonNull(signature, "signature darf nicht null sein");
    }
}
