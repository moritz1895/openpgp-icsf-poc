package ms.rohde.openpgpicsfpoc.ports.outbound.hsm;

import java.util.Objects;
import ms.rohde.openpgpicsfpoc.core.domain.ByteSequence;
import ms.rohde.openpgpicsfpoc.core.domain.HsmKeyHandle;
import org.jspecify.annotations.Nullable;

/**
 * Fluenter Builder fuer eine {@link HsmSignatureRequest}.
 *
 * <p>Reine Zusammenbau-Logik ohne Infrastruktur-Abhaengigkeit - siehe
 * JavaDoc auf {@link HsmRsaEncryption} fuer die Rollentrennung
 * Builder/Executor.</p>
 */
public interface HsmSignature {

    HsmSignature keyHandle(HsmKeyHandle keyHandle);

    HsmSignature algorithm(HsmSignatureAlgorithm algorithm);

    HsmSignature digest(ByteSequence digest);

    HsmSignatureRequest build();

    static HsmSignature builder() {
        return new Default();
    }

    final class Default implements HsmSignature {

        private @Nullable HsmKeyHandle keyHandle;
        private @Nullable HsmSignatureAlgorithm algorithm;
        private @Nullable ByteSequence digest;

        private Default() {}

        @Override
        public HsmSignature keyHandle(HsmKeyHandle keyHandle) {
            this.keyHandle = Objects.requireNonNull(keyHandle, "keyHandle darf nicht null sein");
            return this;
        }

        @Override
        public HsmSignature algorithm(HsmSignatureAlgorithm algorithm) {
            this.algorithm = Objects.requireNonNull(algorithm, "algorithm darf nicht null sein");
            return this;
        }

        @Override
        public HsmSignature digest(ByteSequence digest) {
            this.digest = Objects.requireNonNull(digest, "digest darf nicht null sein");
            return this;
        }

        @Override
        public HsmSignatureRequest build() {
            if (keyHandle == null) {
                throw new IllegalStateException("keyHandle muss gesetzt sein");
            }
            if (algorithm == null) {
                throw new IllegalStateException("algorithm muss gesetzt sein");
            }
            if (digest == null) {
                throw new IllegalStateException("digest muss gesetzt sein");
            }
            return new HsmSignatureRequest(keyHandle, algorithm, digest);
        }
    }
}
