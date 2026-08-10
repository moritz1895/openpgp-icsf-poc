package ms.rohde.openpgpicsfpoc.core.app;

import java.util.Objects;
import ms.rohde.openpgpicsfpoc.core.domain.ByteSequence;
import ms.rohde.openpgpicsfpoc.core.domain.PgpKeyReference;

/**
 * Kommando zum Signieren einer Nachricht.
 */
public record SignOpenPgpMessageCommand(ByteSequence message, PgpKeyReference signer) {

    public SignOpenPgpMessageCommand {
        Objects.requireNonNull(message, "message darf nicht null sein");
        Objects.requireNonNull(signer, "signer darf nicht null sein");
    }
}
