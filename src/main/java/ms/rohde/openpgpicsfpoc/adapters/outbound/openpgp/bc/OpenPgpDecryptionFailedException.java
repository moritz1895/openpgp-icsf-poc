package ms.rohde.openpgpicsfpoc.adapters.outbound.openpgp.bc;

/**
 * Einheitliche, ungeprüfte Fehlermeldung fuer jede Art von
 * Sitzungsschluessel-Wiederherstellungs- oder Integritaetsfehler beim
 * Entschluesseln einer OpenPGP-Nachricht (Padding-Fehlschlag, Prüfsummenfehler,
 * unbekannte Algorithmus-ID, HSM-Ablehnung, MDC-/AEAD-Integritaetsfehler).
 *
 * <p>Diese Bridge meldet absichtlich <b>keine</b> spezifischere Unterklasse
 * je Fehlerursache - das entspricht der in der Feature-Spezifikation
 * "openpgp-encryption" festgelegten Domain Rule 6 (kein Padding-Oracle-artiger
 * Seitenkanal durch unterschiedliche Fehlerklassen fuer unterschiedliche
 * Ursachen).</p>
 */
public final class OpenPgpDecryptionFailedException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public OpenPgpDecryptionFailedException(String message, Throwable cause) {
        super(message, cause);
    }

    public OpenPgpDecryptionFailedException(String message) {
        super(message);
    }
}
