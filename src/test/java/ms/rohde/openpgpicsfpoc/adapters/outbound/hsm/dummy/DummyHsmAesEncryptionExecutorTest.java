package ms.rohde.openpgpicsfpoc.adapters.outbound.hsm.dummy;

import static org.assertj.core.api.Assertions.assertThat;

import java.security.SecureRandom;
import ms.rohde.openpgpicsfpoc.core.domain.ByteSequence;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmAesCipherMode;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmAesEncryption;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmCipherOperation;
import org.junit.jupiter.api.Test;

class DummyHsmAesEncryptionExecutorTest {

    private final DummyHsmAesEncryptionExecutor executor = new DummyHsmAesEncryptionExecutor();

    private static ByteSequence randomBytes(int length) {
        byte[] bytes = new byte[length];
        new SecureRandom().nextBytes(bytes);
        return ByteSequence.of(bytes);
    }

    @Test
    void execute_givenGcmEncryptThenDecrypt_thenRoundTripsToOriginalPlaintext() {
        var sessionKey = randomBytes(32);
        var iv = randomBytes(12);
        var plaintext = ByteSequence.of("the quick brown fox jumps".getBytes());

        var encryptResult = executor.execute(HsmAesEncryption.builder()
                .sessionKey(sessionKey)
                .cipherMode(HsmAesCipherMode.GCM)
                .operation(HsmCipherOperation.ENCRYPT)
                .input(plaintext)
                .initializationVector(iv)
                .build());

        var decryptResult = executor.execute(HsmAesEncryption.builder()
                .sessionKey(sessionKey)
                .cipherMode(HsmAesCipherMode.GCM)
                .operation(HsmCipherOperation.DECRYPT)
                .input(encryptResult.output())
                .initializationVector(iv)
                .authenticationTag(encryptResult.authenticationTag())
                .build());

        assertThat(decryptResult.output()).isEqualTo(plaintext);
    }

    @Test
    void execute_givenCbcEncryptThenDecrypt_thenRoundTripsToOriginalPlaintext() {
        var sessionKey = randomBytes(32);
        var iv = randomBytes(16);
        var plaintext = randomBytes(32);

        var encryptResult = executor.execute(HsmAesEncryption.builder()
                .sessionKey(sessionKey)
                .cipherMode(HsmAesCipherMode.CBC)
                .operation(HsmCipherOperation.ENCRYPT)
                .input(plaintext)
                .initializationVector(iv)
                .build());

        var decryptResult = executor.execute(HsmAesEncryption.builder()
                .sessionKey(sessionKey)
                .cipherMode(HsmAesCipherMode.CBC)
                .operation(HsmCipherOperation.DECRYPT)
                .input(encryptResult.output())
                .initializationVector(iv)
                .build());

        assertThat(decryptResult.output()).isEqualTo(plaintext);
    }

    @Test
    void execute_givenEcbSingleBlockEncryptThenDecrypt_thenRoundTripsToOriginalBlock() {
        var sessionKey = randomBytes(32);
        var block = randomBytes(16);

        var encryptResult = executor.execute(HsmAesEncryption.builder()
                .sessionKey(sessionKey)
                .cipherMode(HsmAesCipherMode.ECB)
                .operation(HsmCipherOperation.ENCRYPT)
                .input(block)
                .build());

        var decryptResult = executor.execute(HsmAesEncryption.builder()
                .sessionKey(sessionKey)
                .cipherMode(HsmAesCipherMode.ECB)
                .operation(HsmCipherOperation.DECRYPT)
                .input(encryptResult.output())
                .build());

        assertThat(decryptResult.output()).isEqualTo(block);
    }
}
