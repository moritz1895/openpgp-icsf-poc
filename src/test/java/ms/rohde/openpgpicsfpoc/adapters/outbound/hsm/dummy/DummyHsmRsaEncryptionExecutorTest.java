package ms.rohde.openpgpicsfpoc.adapters.outbound.hsm.dummy;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.security.KeyPairGenerator;
import ms.rohde.openpgpicsfpoc.core.domain.ByteSequence;
import ms.rohde.openpgpicsfpoc.core.domain.HsmKeyHandle;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmCipherOperation;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmRsaEncryption;
import org.junit.jupiter.api.Test;

class DummyHsmRsaEncryptionExecutorTest {

    @Test
    void execute_givenEncryptThenDecrypt_thenRoundTripsToOriginalPlaintext() throws Exception {
        var keyStore = new InMemoryHsmKeyStore();
        var handle = new HsmKeyHandle("recipient-rsa");
        var keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        keyStore.registerKeyPair(handle, keyPairGenerator.generateKeyPair());
        var executor = new DummyHsmRsaEncryptionExecutor(keyStore);
        var plaintext = ByteSequence.of("session-key-material-32-bytes!!".getBytes());

        var encryptResult = executor.execute(HsmRsaEncryption.builder()
                .keyHandle(handle)
                .operation(HsmCipherOperation.ENCRYPT)
                .input(plaintext)
                .build());
        var decryptResult = executor.execute(HsmRsaEncryption.builder()
                .keyHandle(handle)
                .operation(HsmCipherOperation.DECRYPT)
                .input(encryptResult.output())
                .build());

        assertThat(decryptResult.output()).isEqualTo(plaintext);
    }

    @Test
    void execute_givenUnknownHandle_thenThrowsIllegalStateException() {
        var executor = new DummyHsmRsaEncryptionExecutor(new InMemoryHsmKeyStore());
        var request = HsmRsaEncryption.builder()
                .keyHandle(new HsmKeyHandle("unknown"))
                .operation(HsmCipherOperation.ENCRYPT)
                .input(ByteSequence.of(new byte[] {1}))
                .build();

        assertThatThrownBy(() -> executor.execute(request)).isInstanceOf(IllegalStateException.class);
    }
}
