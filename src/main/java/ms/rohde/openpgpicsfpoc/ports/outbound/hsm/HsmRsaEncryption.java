package ms.rohde.openpgpicsfpoc.ports.outbound.hsm;

import java.util.Objects;
import ms.rohde.openpgpicsfpoc.core.domain.ByteSequence;
import ms.rohde.openpgpicsfpoc.core.domain.HsmKeyHandle;
import org.jspecify.annotations.Nullable;

/**
 * Fluenter Builder fuer eine {@link HsmRsaEncryptionRequest}.
 *
 * <p>Reine Zusammenbau-Logik ohne Infrastruktur-Abhaengigkeit - im
 * Gegensatz zum {@link HsmRsaEncryptionExecutor} (dem eigentlichen
 * Outbound-Port) ist dieser Builder Teil der nachgebildeten proprietaeren
 * Hsm-Primitives-Bibliothek und wird nicht von Adaptern implementiert.</p>
 */
public interface HsmRsaEncryption {

    HsmRsaEncryption keyHandle(HsmKeyHandle keyHandle);

    HsmRsaEncryption operation(HsmCipherOperation operation);

    HsmRsaEncryption input(ByteSequence input);

    HsmRsaEncryptionRequest build();

    static HsmRsaEncryption builder() {
        return new Default();
    }

    final class Default implements HsmRsaEncryption {

        private @Nullable HsmKeyHandle keyHandle;
        private @Nullable HsmCipherOperation operation;
        private @Nullable ByteSequence input;

        private Default() {}

        @Override
        public HsmRsaEncryption keyHandle(HsmKeyHandle keyHandle) {
            this.keyHandle = Objects.requireNonNull(keyHandle, "keyHandle darf nicht null sein");
            return this;
        }

        @Override
        public HsmRsaEncryption operation(HsmCipherOperation operation) {
            this.operation = Objects.requireNonNull(operation, "operation darf nicht null sein");
            return this;
        }

        @Override
        public HsmRsaEncryption input(ByteSequence input) {
            this.input = Objects.requireNonNull(input, "input darf nicht null sein");
            return this;
        }

        @Override
        public HsmRsaEncryptionRequest build() {
            if (keyHandle == null) {
                throw new IllegalStateException("keyHandle muss gesetzt sein");
            }
            if (operation == null) {
                throw new IllegalStateException("operation muss gesetzt sein");
            }
            if (input == null) {
                throw new IllegalStateException("input muss gesetzt sein");
            }
            return new HsmRsaEncryptionRequest(keyHandle, operation, input);
        }
    }
}
