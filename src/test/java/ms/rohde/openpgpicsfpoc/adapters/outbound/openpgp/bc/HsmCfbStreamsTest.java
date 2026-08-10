package ms.rohde.openpgpicsfpoc.adapters.outbound.openpgp.bc;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.SecureRandom;
import ms.rohde.openpgpicsfpoc.adapters.outbound.hsm.dummy.DummyHsmAesEncryptionExecutor;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class HsmCfbStreamsTest {

    private final DummyHsmAesEncryptionExecutor executor = new DummyHsmAesEncryptionExecutor();

    @ParameterizedTest
    @ValueSource(ints = {0, 1, 15, 16, 17, 31, 32, 33, 100, 257})
    void encryptThenDecrypt_givenVariousLengths_thenRecoversOriginalBytes(int length) throws Exception {
        byte[] sessionKey = randomBytes(32);
        byte[] plaintext = randomBytes(length);

        var encryptOut = new ByteArrayOutputStream();
        try (var cfbOut = new HsmCfbOutputStream(encryptOut, new HsmCfbEngine(executor, sessionKey))) {
            cfbOut.write(plaintext);
        }

        var decryptIn = new HsmCfbInputStream(
                new ByteArrayInputStream(encryptOut.toByteArray()), new HsmCfbEngine(executor, sessionKey));
        byte[] recovered = decryptIn.readAllBytes();

        assertThat(recovered).isEqualTo(plaintext);
    }

    @Test
    void encryptThenDecrypt_givenChunkedWrites_thenRecoversOriginalBytes() throws Exception {
        byte[] sessionKey = randomBytes(32);
        byte[] plaintext = randomBytes(500);

        var encryptOut = new ByteArrayOutputStream();
        try (var cfbOut = new HsmCfbOutputStream(encryptOut, new HsmCfbEngine(executor, sessionKey))) {
            for (int offset = 0; offset < plaintext.length; ) {
                int chunk = Math.min(7, plaintext.length - offset);
                cfbOut.write(plaintext, offset, chunk);
                offset += chunk;
            }
        }

        var decryptIn = new HsmCfbInputStream(
                new ByteArrayInputStream(encryptOut.toByteArray()), new HsmCfbEngine(executor, sessionKey));
        byte[] recovered = decryptIn.readAllBytes();

        assertThat(recovered).isEqualTo(plaintext);
    }

    private static byte[] randomBytes(int length) {
        byte[] bytes = new byte[length];
        new SecureRandom().nextBytes(bytes);
        return bytes;
    }
}
