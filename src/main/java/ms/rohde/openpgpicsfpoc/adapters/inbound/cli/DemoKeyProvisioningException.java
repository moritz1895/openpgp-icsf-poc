package ms.rohde.openpgpicsfpoc.adapters.inbound.cli;

/**
 * Wird geworfen, wenn die CLI-Demo beim Start keine Demo-Schluesselpaare erzeugen konnte (z. B.
 * weil ein benoetigter JCA-Algorithmus auf dieser JVM nicht verfuegbar ist).
 */
final class DemoKeyProvisioningException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    DemoKeyProvisioningException(String message, Throwable cause) {
        super(message, cause);
    }
}
