package ms.rohde.openpgpicsfpoc.adapters.outbound.openpgp.bc;

/**
 * Ungeprüfte Fehlermeldung fuer Fehlschlaege beim Erzeugen einer
 * verschluesselten oder signierten OpenPGP-Nachricht sowie beim Parsen einer
 * zu verifizierenden Nachricht (im Gegensatz zu {@link OpenPgpDecryptionFailedException},
 * die speziell die Domain Rule 6 der Feature-Spezifikation "openpgp-encryption"
 * abdeckt).
 */
public final class OpenPgpMessageCodecException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public OpenPgpMessageCodecException(String message, Throwable cause) {
        super(message, cause);
    }
}
