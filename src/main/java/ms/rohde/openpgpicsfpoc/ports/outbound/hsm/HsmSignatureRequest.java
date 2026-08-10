package ms.rohde.openpgpicsfpoc.ports.outbound.hsm;

import java.util.Objects;
import ms.rohde.openpgpicsfpoc.core.domain.ByteSequence;
import ms.rohde.openpgpicsfpoc.core.domain.HsmKeyHandle;

/**
 * Unveraenderliches Ausfuehrungsobjekt fuer eine Signaturoperation. Wird
 * ueber {@link HsmSignature} zusammengebaut und von
 * {@link HsmSignatureExecutor} ausgefuehrt.
 *
 * <p>Das Hashing erfolgt stets lokal, ausserhalb der HSM (siehe
 * {@code MessageDigestCalculator}); nur der finale Signaturschritt ueber den
 * bereits berechneten Digest wird an die HSM gegeben. Fuer
 * {@link HsmSignatureAlgorithm#EDDSA} weicht das vom "pure EdDSA"-Schema ab,
 * das ueblicherweise direkt ueber die Rohnachricht statt ueber einen
 * vorberechneten Digest signiert - eine bewusste, dokumentierte
 * Vereinfachung dieser PoC zugunsten eines einheitlichen, algorithmus-
 * agnostischen Ports.</p>
 */
public record HsmSignatureRequest(HsmKeyHandle keyHandle, HsmSignatureAlgorithm algorithm, ByteSequence digest) {

    public HsmSignatureRequest {
        Objects.requireNonNull(keyHandle, "keyHandle darf nicht null sein");
        Objects.requireNonNull(algorithm, "algorithm darf nicht null sein");
        Objects.requireNonNull(digest, "digest darf nicht null sein");
        if (digest.isEmpty()) {
            throw new IllegalArgumentException("digest darf nicht leer sein");
        }
    }
}
