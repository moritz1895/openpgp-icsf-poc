package ms.rohde.openpgpicsfpoc.ports.outbound.hsm;

import java.util.Objects;
import ms.rohde.openpgpicsfpoc.core.domain.ByteSequence;
import ms.rohde.openpgpicsfpoc.core.domain.HsmKeyHandle;
import org.jspecify.annotations.Nullable;

/**
 * Fluenter Builder fuer eine {@link HsmKeyEncapsulationRequest}.
 *
 * <p>Reine Zusammenbau-Logik ohne Infrastruktur-Abhaengigkeit - siehe
 * JavaDoc auf {@link HsmRsaEncryption} fuer die Rollentrennung
 * Builder/Executor.</p>
 */
public interface HsmKeyEncapsulation {

    HsmKeyEncapsulation keyHandle(HsmKeyHandle keyHandle);

    HsmKeyEncapsulation operation(HsmKeyEncapsulationOperation operation);

    HsmKeyEncapsulation encapsulatedKey(@Nullable ByteSequence encapsulatedKey);

    HsmKeyEncapsulationRequest build();

    static HsmKeyEncapsulation builder() {
        return new Default();
    }

    final class Default implements HsmKeyEncapsulation {

        private @Nullable HsmKeyHandle keyHandle;
        private @Nullable HsmKeyEncapsulationOperation operation;
        private @Nullable ByteSequence encapsulatedKey;

        private Default() {}

        @Override
        public HsmKeyEncapsulation keyHandle(HsmKeyHandle keyHandle) {
            this.keyHandle = Objects.requireNonNull(keyHandle, "keyHandle darf nicht null sein");
            return this;
        }

        @Override
        public HsmKeyEncapsulation operation(HsmKeyEncapsulationOperation operation) {
            this.operation = Objects.requireNonNull(operation, "operation darf nicht null sein");
            return this;
        }

        @Override
        public HsmKeyEncapsulation encapsulatedKey(@Nullable ByteSequence encapsulatedKey) {
            this.encapsulatedKey = encapsulatedKey;
            return this;
        }

        @Override
        public HsmKeyEncapsulationRequest build() {
            if (keyHandle == null) {
                throw new IllegalStateException("keyHandle muss gesetzt sein");
            }
            if (operation == null) {
                throw new IllegalStateException("operation muss gesetzt sein");
            }
            return new HsmKeyEncapsulationRequest(keyHandle, operation, encapsulatedKey);
        }
    }
}
