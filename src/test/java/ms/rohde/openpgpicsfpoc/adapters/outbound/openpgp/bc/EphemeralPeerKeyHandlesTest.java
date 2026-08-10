package ms.rohde.openpgpicsfpoc.adapters.outbound.openpgp.bc;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class EphemeralPeerKeyHandlesTest {

    @Test
    void deriveFrom_givenSameBytes_thenReturnsSameHandle() {
        byte[] point = {1, 2, 3, 4, 5};

        var first = EphemeralPeerKeyHandles.deriveFrom(point);
        var second = EphemeralPeerKeyHandles.deriveFrom(point.clone());

        assertThat(first).isEqualTo(second);
    }

    @Test
    void deriveFrom_givenDifferentBytes_thenReturnsDifferentHandle() {
        var first = EphemeralPeerKeyHandles.deriveFrom(new byte[] {1, 2, 3});
        var second = EphemeralPeerKeyHandles.deriveFrom(new byte[] {1, 2, 4});

        assertThat(first).isNotEqualTo(second);
    }
}
