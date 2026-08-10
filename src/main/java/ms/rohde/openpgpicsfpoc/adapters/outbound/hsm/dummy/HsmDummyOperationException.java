package ms.rohde.openpgpicsfpoc.adapters.outbound.hsm.dummy;

/**
 * <b>Kein Produktivcode - reines Testdouble.</b>
 *
 * <p>Ungeprüfte Wrapper-Exception fuer checked {@code java.security}/
 * {@code javax.crypto}-Ausnahmen, die innerhalb der Dummy-Hsm-Executoren
 * auftreten. Ein echter ICSF-Adapter wuerde stattdessen eine eigene,
 * ICSF-spezifische Fehlerhierarchie verwenden.
 */
public final class HsmDummyOperationException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public HsmDummyOperationException(String message, Throwable cause) {
        super(message, cause);
    }
}
