package ms.rohde.openpgpicsfpoc.ports.outbound.hsm;

import java.util.Objects;
import ms.rohde.openpgpicsfpoc.core.domain.ByteSequence;
import ms.rohde.openpgpicsfpoc.core.domain.HsmKeyHandle;
import org.jspecify.annotations.Nullable;

/**
 * Unveraenderliches Ausfuehrungsobjekt fuer eine ML-KEM-768-Operation. Wird
 * ueber {@link HsmKeyEncapsulation} zusammengebaut und von
 * {@link HsmKeyEncapsulationExecutor} ausgefuehrt.
 *
 * <p>Bei {@link HsmKeyEncapsulationOperation#ENCAPSULATE} referenziert
 * {@code keyHandle} den vorab im HSM registrierten oeffentlichen
 * ML-KEM-768-Schluessel der Gegenstelle, {@code encapsulatedKey} bleibt
 * leer (er wird als Ergebnis der Operation erzeugt). Bei
 * {@link HsmKeyEncapsulationOperation#DECAPSULATE} referenziert
 * {@code keyHandle} den eigenen privaten Schluessel und
 * {@code encapsulatedKey} enthaelt das empfangene KEM-Chiffrat.</p>
 */
public record HsmKeyEncapsulationRequest(
        HsmKeyHandle keyHandle, HsmKeyEncapsulationOperation operation, @Nullable ByteSequence encapsulatedKey) {

    public HsmKeyEncapsulationRequest {
        Objects.requireNonNull(keyHandle, "keyHandle darf nicht null sein");
        Objects.requireNonNull(operation, "operation darf nicht null sein");
        if (operation == HsmKeyEncapsulationOperation.DECAPSULATE && encapsulatedKey == null) {
            throw new IllegalArgumentException("DECAPSULATE benoetigt encapsulatedKey");
        }
        if (operation == HsmKeyEncapsulationOperation.ENCAPSULATE && encapsulatedKey != null) {
            throw new IllegalArgumentException("ENCAPSULATE darf kein encapsulatedKey enthalten");
        }
    }
}
