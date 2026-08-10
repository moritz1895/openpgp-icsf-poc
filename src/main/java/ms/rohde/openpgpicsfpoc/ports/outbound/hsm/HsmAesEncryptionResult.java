package ms.rohde.openpgpicsfpoc.ports.outbound.hsm;

import java.util.Objects;
import ms.rohde.openpgpicsfpoc.core.domain.ByteSequence;
import org.jspecify.annotations.Nullable;

/**
 * Ergebnis einer {@link HsmAesEncryptionExecutor}-Ausfuehrung.
 * {@code authenticationTag} ist nur bei {@link HsmAesCipherMode#GCM} und nur
 * fuer die Verschluesselungsrichtung gesetzt.
 */
public record HsmAesEncryptionResult(ByteSequence output, @Nullable ByteSequence authenticationTag) {

    public HsmAesEncryptionResult {
        Objects.requireNonNull(output, "output darf nicht null sein");
    }
}
