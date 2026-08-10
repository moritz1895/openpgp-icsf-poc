package ms.rohde.openpgpicsfpoc.ports.outbound.hsm;

import java.util.Objects;
import ms.rohde.openpgpicsfpoc.core.domain.ByteSequence;

/**
 * Ergebnis einer {@link HsmRsaEncryptionExecutor}-Ausfuehrung.
 */
public record HsmRsaEncryptionResult(ByteSequence output) {

    public HsmRsaEncryptionResult {
        Objects.requireNonNull(output, "output darf nicht null sein");
    }
}
