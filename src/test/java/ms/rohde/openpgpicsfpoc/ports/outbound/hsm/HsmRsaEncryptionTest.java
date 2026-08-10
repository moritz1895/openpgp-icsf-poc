package ms.rohde.openpgpicsfpoc.ports.outbound.hsm;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import ms.rohde.openpgpicsfpoc.core.domain.ByteSequence;
import ms.rohde.openpgpicsfpoc.core.domain.HsmKeyHandle;
import org.junit.jupiter.api.Test;

class HsmRsaEncryptionTest {

    @Test
    void build_givenAllFieldsSet_thenReturnsRequest() {
        var request = HsmRsaEncryption.builder()
                .keyHandle(new HsmKeyHandle("recipient-rsa"))
                .operation(HsmCipherOperation.ENCRYPT)
                .input(ByteSequence.of(new byte[] {1, 2, 3}))
                .build();

        assertThat(request.keyHandle()).isEqualTo(new HsmKeyHandle("recipient-rsa"));
        assertThat(request.operation()).isEqualTo(HsmCipherOperation.ENCRYPT);
        assertThat(request.input().length()).isEqualTo(3);
    }

    @Test
    void build_givenMissingKeyHandle_thenThrowsIllegalStateException() {
        var builder = HsmRsaEncryption.builder()
                .operation(HsmCipherOperation.ENCRYPT)
                .input(ByteSequence.of(new byte[] {1}));

        assertThatThrownBy(builder::build).isInstanceOf(IllegalStateException.class);
    }

    @Test
    void build_givenMissingOperation_thenThrowsIllegalStateException() {
        var builder = HsmRsaEncryption.builder()
                .keyHandle(new HsmKeyHandle("recipient-rsa"))
                .input(ByteSequence.of(new byte[] {1}));

        assertThatThrownBy(builder::build).isInstanceOf(IllegalStateException.class);
    }

    @Test
    void build_givenMissingInput_thenThrowsIllegalStateException() {
        var builder = HsmRsaEncryption.builder()
                .keyHandle(new HsmKeyHandle("recipient-rsa"))
                .operation(HsmCipherOperation.DECRYPT);

        assertThatThrownBy(builder::build).isInstanceOf(IllegalStateException.class);
    }
}
