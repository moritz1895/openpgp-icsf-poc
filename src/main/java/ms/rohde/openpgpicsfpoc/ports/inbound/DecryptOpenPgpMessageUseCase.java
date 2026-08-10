package ms.rohde.openpgpicsfpoc.ports.inbound;

import ms.rohde.hexagonalarch.annotations.DrivingPort;
import ms.rohde.openpgpicsfpoc.core.app.DecryptOpenPgpMessageCommand;
import ms.rohde.openpgpicsfpoc.core.domain.ByteSequence;

/**
 * Treibender Port zum Entschluesseln einer OpenPGP-Nachricht mit dem eigenen
 * (HSM-referenzierten) Schluessel.
 */
@DrivingPort
public interface DecryptOpenPgpMessageUseCase {

    /**
     * Entschluesselt die Nachricht aus dem Kommando und liefert den
     * Klartext.
     */
    ByteSequence decrypt(DecryptOpenPgpMessageCommand command);
}
