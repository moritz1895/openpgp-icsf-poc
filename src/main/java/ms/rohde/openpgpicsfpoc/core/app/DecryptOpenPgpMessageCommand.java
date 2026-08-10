package ms.rohde.openpgpicsfpoc.core.app;

import java.util.Objects;
import ms.rohde.openpgpicsfpoc.core.domain.OpenPgpMessage;
import ms.rohde.openpgpicsfpoc.core.domain.PgpKeyReference;

/**
 * Kommando zum Entschluesseln einer OpenPGP-Nachricht mit dem eigenen
 * Schluessel des Empfaengers.
 */
public record DecryptOpenPgpMessageCommand(OpenPgpMessage message, PgpKeyReference recipient) {

    public DecryptOpenPgpMessageCommand {
        Objects.requireNonNull(message, "message darf nicht null sein");
        Objects.requireNonNull(recipient, "recipient darf nicht null sein");
    }
}
