package ms.rohde.openpgpicsfpoc.ports.outbound.hsm;

import java.util.Objects;
import ms.rohde.openpgpicsfpoc.core.domain.ByteSequence;

/**
 * Ergebnis einer {@link HsmSignatureExecutor}-Ausfuehrung.
 */
public record HsmSignatureResult(ByteSequence signature) {

    public HsmSignatureResult {
        Objects.requireNonNull(signature, "signature darf nicht null sein");
    }
}
