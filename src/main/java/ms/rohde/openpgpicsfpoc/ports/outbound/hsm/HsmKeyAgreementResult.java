package ms.rohde.openpgpicsfpoc.ports.outbound.hsm;

import java.util.Objects;
import ms.rohde.openpgpicsfpoc.core.domain.ByteSequence;

/**
 * Ergebnis einer {@link HsmKeyAgreementExecutor}-Ausfuehrung.
 */
public record HsmKeyAgreementResult(ByteSequence sharedSecret) {

    public HsmKeyAgreementResult {
        Objects.requireNonNull(sharedSecret, "sharedSecret darf nicht null sein");
    }
}
