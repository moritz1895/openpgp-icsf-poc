package ms.rohde.openpgpicsfpoc.ports.outbound.hsm;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import ms.rohde.openpgpicsfpoc.core.domain.ByteSequence;
import org.junit.jupiter.api.Test;

class HsmAesEncryptionTest {

    private static ByteSequence bytes(int length) {
        return ByteSequence.of(new byte[length]);
    }

    @Test
    void build_givenGcmWithIv_thenReturnsRequest() {
        var request = HsmAesEncryption.builder()
                .sessionKey(bytes(32))
                .cipherMode(HsmAesCipherMode.GCM)
                .operation(HsmCipherOperation.ENCRYPT)
                .input(bytes(64))
                .initializationVector(bytes(12))
                .build();

        assertThat(request.cipherMode()).isEqualTo(HsmAesCipherMode.GCM);
        assertThat(request.initializationVector()).isEqualTo(bytes(12));
    }

    @Test
    void build_givenGcmWithoutIv_thenThrowsIllegalArgumentException() {
        var builder = HsmAesEncryption.builder()
                .sessionKey(bytes(32))
                .cipherMode(HsmAesCipherMode.GCM)
                .operation(HsmCipherOperation.ENCRYPT)
                .input(bytes(64));

        assertThatThrownBy(builder::build).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void build_givenGcmDecryptWithoutAuthenticationTag_thenThrowsIllegalArgumentException() {
        var builder = HsmAesEncryption.builder()
                .sessionKey(bytes(32))
                .cipherMode(HsmAesCipherMode.GCM)
                .operation(HsmCipherOperation.DECRYPT)
                .input(bytes(64))
                .initializationVector(bytes(12));

        assertThatThrownBy(builder::build).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void build_givenEcbWithSingleBlock_thenReturnsRequest() {
        var request = HsmAesEncryption.builder()
                .sessionKey(bytes(32))
                .cipherMode(HsmAesCipherMode.ECB)
                .operation(HsmCipherOperation.ENCRYPT)
                .input(bytes(16))
                .build();

        assertThat(request.input().length()).isEqualTo(16);
    }

    @Test
    void build_givenEcbWithMoreThanOneBlock_thenThrowsIllegalArgumentException() {
        var builder = HsmAesEncryption.builder()
                .sessionKey(bytes(32))
                .cipherMode(HsmAesCipherMode.ECB)
                .operation(HsmCipherOperation.ENCRYPT)
                .input(bytes(32));

        assertThatThrownBy(builder::build).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void build_givenEcbWithInitializationVector_thenThrowsIllegalArgumentException() {
        var builder = HsmAesEncryption.builder()
                .sessionKey(bytes(32))
                .cipherMode(HsmAesCipherMode.ECB)
                .operation(HsmCipherOperation.ENCRYPT)
                .input(bytes(16))
                .initializationVector(bytes(16));

        assertThatThrownBy(builder::build).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void build_givenCbcWithoutIv_thenThrowsIllegalArgumentException() {
        var builder = HsmAesEncryption.builder()
                .sessionKey(bytes(32))
                .cipherMode(HsmAesCipherMode.CBC)
                .operation(HsmCipherOperation.ENCRYPT)
                .input(bytes(32));

        assertThatThrownBy(builder::build).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void build_givenMissingSessionKey_thenThrowsIllegalStateException() {
        var builder = HsmAesEncryption.builder()
                .cipherMode(HsmAesCipherMode.ECB)
                .operation(HsmCipherOperation.ENCRYPT)
                .input(bytes(16));

        assertThatThrownBy(builder::build).isInstanceOf(IllegalStateException.class);
    }
}
