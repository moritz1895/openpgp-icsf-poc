package ms.rohde.openpgpicsfpoc.ports.outbound;

import java.util.Objects;
import ms.rohde.openpgpicsfpoc.core.domain.OpenPgpMessage;
import ms.rohde.openpgpicsfpoc.core.domain.PgpKeyReference;

/**
 * Anfrage an {@link OpenPgpMessageCodec#decrypt(OpenPgpDecryptionRequest)}:
 * die verschluesselte OpenPGP-Nachricht sowie der Schluessel-Handle, mit dem
 * der Empfaenger sie zu entschluesseln versucht. Das Parsen des Paketformats,
 * das Aufloesen des Sitzungsschluessels (bzw. des gemeinsamen Shared Secrets)
 * ueber die passende Hsm-Primitive sowie die Nutzlastentschluesselung
 * obliegen vollstaendig der Implementierung dieses Ports.
 */
public record OpenPgpDecryptionRequest(OpenPgpMessage message, PgpKeyReference recipient) {

    public OpenPgpDecryptionRequest {
        Objects.requireNonNull(message, "message darf nicht null sein");
        Objects.requireNonNull(recipient, "recipient darf nicht null sein");
    }
}
