package ms.rohde.openpgpicsfpoc.adapters.outbound.openpgp.bc;

/**
 * Wird geworfen, wenn die RFC-3394-Integritaetspruefung (das feste
 * Initialisierungsvektor-Praefix {@code A6A6A6A6A6A6A6A6}) beim Entpacken
 * eines verpackten Sitzungsschluessels nicht aufgeht - typischerweise, weil
 * der falsche Schluessel-Wickel-Schluessel abgeleitet wurde (z. B. ein
 * falscher HSM-Schluesselaustausch-Partner).
 */
final class HsmAesKeyUnwrapIntegrityException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    HsmAesKeyUnwrapIntegrityException() {
        super("RFC-3394-Integritaetspruefung beim Schluessel-Entpacken fehlgeschlagen");
    }
}
