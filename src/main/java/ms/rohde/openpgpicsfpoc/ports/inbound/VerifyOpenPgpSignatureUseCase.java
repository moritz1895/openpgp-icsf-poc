package ms.rohde.openpgpicsfpoc.ports.inbound;

import ms.rohde.hexagonalarch.annotations.DrivingPort;
import ms.rohde.openpgpicsfpoc.core.app.VerifyOpenPgpSignatureCommand;

/**
 * Treibender Port zum Verifizieren einer signierten OpenPGP-Nachricht.
 */
@DrivingPort
public interface VerifyOpenPgpSignatureUseCase {

    /**
     * Prueft die Signatur der Nachricht gegen den oeffentlichen Schluessel
     * des Unterzeichners. Reine lokale Operation, keine HSM-Abhaengigkeit.
     */
    boolean verify(VerifyOpenPgpSignatureCommand command);
}
