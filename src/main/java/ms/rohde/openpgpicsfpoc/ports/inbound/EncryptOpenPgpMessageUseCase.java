package ms.rohde.openpgpicsfpoc.ports.inbound;

import ms.rohde.hexagonalarch.annotations.DrivingPort;
import ms.rohde.openpgpicsfpoc.core.app.EncryptOpenPgpMessageCommand;
import ms.rohde.openpgpicsfpoc.core.domain.OpenPgpMessage;

/**
 * Treibender Port zum Verschluesseln einer Nachricht als OpenPGP-Nachricht
 * fuer einen Empfaenger.
 */
@DrivingPort
public interface EncryptOpenPgpMessageUseCase {

    /**
     * Verschluesselt den Klartext aus dem Kommando fuer den angegebenen
     * Empfaenger im gewaehlten Verschluesselungsprofil.
     */
    OpenPgpMessage encrypt(EncryptOpenPgpMessageCommand command);
}
