package ms.rohde.openpgpicsfpoc.ports.outbound.hsm;

import java.util.Objects;
import ms.rohde.openpgpicsfpoc.core.domain.ByteSequence;
import org.jspecify.annotations.Nullable;

/**
 * Fluenter Builder fuer eine {@link HsmAesEncryptionRequest}.
 *
 * <p>Reine Zusammenbau-Logik ohne Infrastruktur-Abhaengigkeit - siehe
 * JavaDoc auf {@link HsmRsaEncryption} fuer die Rollentrennung
 * Builder/Executor.</p>
 */
public interface HsmAesEncryption {

    HsmAesEncryption sessionKey(ByteSequence sessionKey);

    HsmAesEncryption cipherMode(HsmAesCipherMode cipherMode);

    HsmAesEncryption operation(HsmCipherOperation operation);

    HsmAesEncryption input(ByteSequence input);

    HsmAesEncryption initializationVector(@Nullable ByteSequence initializationVector);

    HsmAesEncryption additionalAuthenticatedData(@Nullable ByteSequence additionalAuthenticatedData);

    HsmAesEncryption authenticationTag(@Nullable ByteSequence authenticationTag);

    HsmAesEncryptionRequest build();

    static HsmAesEncryption builder() {
        return new Default();
    }

    final class Default implements HsmAesEncryption {

        private @Nullable ByteSequence sessionKey;
        private @Nullable HsmAesCipherMode cipherMode;
        private @Nullable HsmCipherOperation operation;
        private @Nullable ByteSequence input;
        private @Nullable ByteSequence initializationVector;
        private @Nullable ByteSequence additionalAuthenticatedData;
        private @Nullable ByteSequence authenticationTag;

        private Default() {}

        @Override
        public HsmAesEncryption sessionKey(ByteSequence sessionKey) {
            this.sessionKey = Objects.requireNonNull(sessionKey, "sessionKey darf nicht null sein");
            return this;
        }

        @Override
        public HsmAesEncryption cipherMode(HsmAesCipherMode cipherMode) {
            this.cipherMode = Objects.requireNonNull(cipherMode, "cipherMode darf nicht null sein");
            return this;
        }

        @Override
        public HsmAesEncryption operation(HsmCipherOperation operation) {
            this.operation = Objects.requireNonNull(operation, "operation darf nicht null sein");
            return this;
        }

        @Override
        public HsmAesEncryption input(ByteSequence input) {
            this.input = Objects.requireNonNull(input, "input darf nicht null sein");
            return this;
        }

        @Override
        public HsmAesEncryption initializationVector(@Nullable ByteSequence initializationVector) {
            this.initializationVector = initializationVector;
            return this;
        }

        @Override
        public HsmAesEncryption additionalAuthenticatedData(@Nullable ByteSequence additionalAuthenticatedData) {
            this.additionalAuthenticatedData = additionalAuthenticatedData;
            return this;
        }

        @Override
        public HsmAesEncryption authenticationTag(@Nullable ByteSequence authenticationTag) {
            this.authenticationTag = authenticationTag;
            return this;
        }

        @Override
        public HsmAesEncryptionRequest build() {
            if (sessionKey == null) {
                throw new IllegalStateException("sessionKey muss gesetzt sein");
            }
            if (cipherMode == null) {
                throw new IllegalStateException("cipherMode muss gesetzt sein");
            }
            if (operation == null) {
                throw new IllegalStateException("operation muss gesetzt sein");
            }
            if (input == null) {
                throw new IllegalStateException("input muss gesetzt sein");
            }
            return new HsmAesEncryptionRequest(
                    sessionKey, cipherMode, operation, input, initializationVector, additionalAuthenticatedData,
                    authenticationTag);
        }
    }
}
