package ms.rohde.openpgpicsfpoc.core.app;

import java.util.Objects;
import ms.rohde.openpgpicsfpoc.core.domain.OpenPgpMessage;
import ms.rohde.openpgpicsfpoc.core.domain.PgpPublicKey;

/**
 * Kommando zum Verifizieren einer signierten OpenPGP-Nachricht.
 */
public record VerifyOpenPgpSignatureCommand(OpenPgpMessage signedMessage, PgpPublicKey signerPublicKey) {

    public VerifyOpenPgpSignatureCommand {
        Objects.requireNonNull(signedMessage, "signedMessage darf nicht null sein");
        Objects.requireNonNull(signerPublicKey, "signerPublicKey darf nicht null sein");
    }
}
