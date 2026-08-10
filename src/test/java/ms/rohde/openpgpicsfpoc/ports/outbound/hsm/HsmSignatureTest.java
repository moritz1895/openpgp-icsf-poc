package ms.rohde.openpgpicsfpoc.ports.outbound.hsm;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import ms.rohde.openpgpicsfpoc.core.domain.ByteSequence;
import ms.rohde.openpgpicsfpoc.core.domain.HsmKeyHandle;
import org.junit.jupiter.api.Test;

class HsmSignatureTest {

    @Test
    void build_givenAllFieldsSet_thenReturnsRequest() {
        var request = HsmSignature.builder()
                .keyHandle(new HsmKeyHandle("signer-eddsa"))
                .algorithm(HsmSignatureAlgorithm.EDDSA)
                .digest(ByteSequence.of(new byte[32]))
                .build();

        assertThat(request.algorithm()).isEqualTo(HsmSignatureAlgorithm.EDDSA);
        assertThat(request.digest().length()).isEqualTo(32);
    }

    @Test
    void build_givenMissingAlgorithm_thenThrowsIllegalStateException() {
        var builder = HsmSignature.builder()
                .keyHandle(new HsmKeyHandle("signer-eddsa"))
                .digest(ByteSequence.of(new byte[32]));

        assertThatThrownBy(builder::build).isInstanceOf(IllegalStateException.class);
    }
}
