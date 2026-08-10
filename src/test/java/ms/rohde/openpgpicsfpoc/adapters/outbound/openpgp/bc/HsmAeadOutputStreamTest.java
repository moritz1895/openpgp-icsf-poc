package ms.rohde.openpgpicsfpoc.adapters.outbound.openpgp.bc;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.ByteArrayOutputStream;
import java.security.SecureRandom;
import ms.rohde.openpgpicsfpoc.adapters.outbound.hsm.dummy.DummyHsmAesEncryptionExecutor;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Rundlauf-Test fuer den AEAD-Chunk-Codec des modernen Verschluesselungsprofils
 * (SEIPD v2): verschluesselt ueber {@link HsmAeadOutputStream}, entschluesselt
 * ueber dieselbe Chunk-Logik wie {@link HsmSymmetricDecryptorSupport}.
 */
class HsmAeadOutputStreamTest {

    private static final int CHUNK_SIZE_OCTET = 0; // 64-Byte-Chunks - erzwingt mehrere Chunks in den Tests

    private final DummyHsmAesEncryptionExecutor executor = new DummyHsmAesEncryptionExecutor();

    @ParameterizedTest
    @ValueSource(ints = {0, 1, 63, 64, 65, 130, 200})
    void encryptThenDecrypt_givenVariousLengths_thenRecoversOriginalBytes(int length) throws Exception {
        byte[] messageKey = randomBytes(32);
        byte[] iv = randomBytes(12);
        byte[] aaData = randomBytes(5);
        byte[] plaintext = randomBytes(length);

        var encryptOut = new ByteArrayOutputStream();
        var encryptCodec = new HsmAeadChunkCodec(executor, messageKey, iv, aaData);
        try (var aeadOut = new HsmAeadOutputStream(encryptOut, encryptCodec, CHUNK_SIZE_OCTET)) {
            aeadOut.write(plaintext);
        }

        byte[] recovered = decryptAll(encryptOut.toByteArray(), messageKey, iv, aaData);

        assertThat(recovered).isEqualTo(plaintext);
    }

    @Test
    void decrypt_givenTamperedCiphertext_thenThrowsDecryptionFailedException() {
        byte[] messageKey = randomBytes(32);
        byte[] iv = randomBytes(12);
        byte[] aaData = randomBytes(5);
        byte[] plaintext = randomBytes(100);

        var encryptOut = new ByteArrayOutputStream();
        var encryptCodec = new HsmAeadChunkCodec(executor, messageKey, iv, aaData);
        try (var aeadOut = new HsmAeadOutputStream(encryptOut, encryptCodec, CHUNK_SIZE_OCTET)) {
            aeadOut.write(plaintext);
        } catch (java.io.IOException e) {
            throw new AssertionError(e);
        }

        byte[] tampered = encryptOut.toByteArray();
        tampered[0] ^= 0x01;

        org.assertj.core.api.Assertions.assertThatThrownBy(() -> decryptAll(tampered, messageKey, iv, aaData))
                .isInstanceOf(OpenPgpDecryptionFailedException.class);
    }

    private byte[] decryptAll(byte[] wireBytes, byte[] messageKey, byte[] iv, byte[] aaData) {
        var decryptCodec = new HsmAeadChunkCodec(executor, messageKey, iv, aaData);
        long chunkLength = HsmAeadChunkCodec.chunkLength(CHUNK_SIZE_OCTET);
        int recordLength = (int) chunkLength + HsmAeadChunkCodec.TAG_LENGTH;
        int chunkBytesTotal = wireBytes.length - HsmAeadChunkCodec.TAG_LENGTH;

        var plaintext = new java.io.ByteArrayOutputStream();
        long chunkIndex = 0;
        int offset = 0;
        while (offset < chunkBytesTotal) {
            int thisRecordLength = Math.min(recordLength, chunkBytesTotal - offset);
            byte[] record = java.util.Arrays.copyOfRange(wireBytes, offset, offset + thisRecordLength);
            plaintext.writeBytes(decryptCodec.decryptChunk(record, chunkIndex));
            offset += thisRecordLength;
            chunkIndex++;
        }
        byte[] finalTag = java.util.Arrays.copyOfRange(wireBytes, chunkBytesTotal, wireBytes.length);
        decryptCodec.verifyFinalTag(finalTag, chunkIndex, plaintext.size());
        return plaintext.toByteArray();
    }

    private static byte[] randomBytes(int length) {
        byte[] bytes = new byte[length];
        new SecureRandom().nextBytes(bytes);
        return bytes;
    }
}
