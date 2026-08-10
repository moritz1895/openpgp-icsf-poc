package ms.rohde.openpgpicsfpoc.ports.outbound.hsm;

import java.util.Objects;
import ms.rohde.openpgpicsfpoc.core.domain.ByteSequence;
import org.jspecify.annotations.Nullable;

/**
 * Ergebnis einer {@link HsmKeyEncapsulationExecutor}-Ausfuehrung.
 * {@code encapsulatedKey} ist nur bei {@link HsmKeyEncapsulationOperation#ENCAPSULATE}
 * gesetzt (das an die Gegenstelle zu uebermittelnde KEM-Chiffrat).
 */
public record HsmKeyEncapsulationResult(ByteSequence sharedSecret, @Nullable ByteSequence encapsulatedKey) {

    public HsmKeyEncapsulationResult {
        Objects.requireNonNull(sharedSecret, "sharedSecret darf nicht null sein");
    }
}
