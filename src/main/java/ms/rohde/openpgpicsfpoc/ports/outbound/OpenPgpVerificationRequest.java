package ms.rohde.openpgpicsfpoc.ports.outbound;

import java.util.Objects;
import ms.rohde.openpgpicsfpoc.core.domain.OpenPgpMessage;
import ms.rohde.openpgpicsfpoc.core.domain.PgpPublicKey;

/**
 * Anfrage an {@link OpenPgpMessageCodec#verify(OpenPgpVerificationRequest)}.
 * Verifikation ist eine reine, lokale Public-Key-Operation ohne HSM-Bezug
 * (siehe Projektplan) - der Codec fuehrt Parsen und kryptographische Pruefung
 * in einem Schritt aus.
 */
public record OpenPgpVerificationRequest(OpenPgpMessage signedMessage, PgpPublicKey signerPublicKey) {

    public OpenPgpVerificationRequest {
        Objects.requireNonNull(signedMessage, "signedMessage darf nicht null sein");
        Objects.requireNonNull(signerPublicKey, "signerPublicKey darf nicht null sein");
    }
}
