package ms.rohde.openpgpicsfpoc.ports.inbound;

import ms.rohde.hexagonalarch.annotations.DrivingPort;
import ms.rohde.openpgpicsfpoc.core.app.SignOpenPgpMessageCommand;
import ms.rohde.openpgpicsfpoc.core.domain.OpenPgpMessage;

/**
 * Treibender Port zum Signieren einer Nachricht als OpenPGP-Nachricht.
 */
@DrivingPort
public interface SignOpenPgpMessageUseCase {

    /**
     * Signiert die Nachricht aus dem Kommando mit dem Schluessel des
     * Unterzeichners.
     */
    OpenPgpMessage sign(SignOpenPgpMessageCommand command);
}
