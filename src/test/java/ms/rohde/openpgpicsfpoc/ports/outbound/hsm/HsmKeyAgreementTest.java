package ms.rohde.openpgpicsfpoc.ports.outbound.hsm;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import ms.rohde.openpgpicsfpoc.core.domain.HsmKeyHandle;
import org.junit.jupiter.api.Test;

class HsmKeyAgreementTest {

    @Test
    void build_givenAllFieldsSet_thenReturnsRequest() {
        var request = HsmKeyAgreement.builder()
                .curve(HsmEllipticCurve.X25519)
                .localKeyHandle(new HsmKeyHandle("sender-x25519"))
                .peerKeyHandle(new HsmKeyHandle("recipient-x25519"))
                .build();

        assertThat(request.curve()).isEqualTo(HsmEllipticCurve.X25519);
        assertThat(request.localKeyHandle()).isEqualTo(new HsmKeyHandle("sender-x25519"));
        assertThat(request.peerKeyHandle()).isEqualTo(new HsmKeyHandle("recipient-x25519"));
    }

    @Test
    void build_givenMissingPeerKeyHandle_thenThrowsIllegalStateException() {
        var builder = HsmKeyAgreement.builder()
                .curve(HsmEllipticCurve.P256)
                .localKeyHandle(new HsmKeyHandle("sender-p256"));

        assertThatThrownBy(builder::build).isInstanceOf(IllegalStateException.class);
    }
}
