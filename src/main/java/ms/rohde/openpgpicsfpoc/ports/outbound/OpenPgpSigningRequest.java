package ms.rohde.openpgpicsfpoc.ports.outbound;

import java.util.Objects;
import ms.rohde.openpgpicsfpoc.core.domain.ByteSequence;
import ms.rohde.openpgpicsfpoc.core.domain.PgpKeyReference;

/**
 * Anfrage an {@link OpenPgpMessageCodec#sign(OpenPgpSigningRequest)}: die zu
 * signierende Nachricht sowie der Schluessel-Handle des Unterzeichners. Die
 * lokale Digest-Berechnung sowie der ueber die HSM delegierte
 * Signaturschritt obliegen vollstaendig der Implementierung dieses Ports.
 */
public record OpenPgpSigningRequest(ByteSequence message, PgpKeyReference signer) {

    public OpenPgpSigningRequest {
        Objects.requireNonNull(message, "message darf nicht null sein");
        Objects.requireNonNull(signer, "signer darf nicht null sein");
    }
}
