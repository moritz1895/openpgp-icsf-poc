package ms.rohde.openpgpicsfpoc.ports.outbound.hsm;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import ms.rohde.openpgpicsfpoc.core.domain.ByteSequence;
import ms.rohde.openpgpicsfpoc.core.domain.HsmKeyHandle;
import org.junit.jupiter.api.Test;

class HsmKeyEncapsulationTest {

    @Test
    void build_givenEncapsulate_thenReturnsRequestWithoutEncapsulatedKey() {
        var request = HsmKeyEncapsulation.builder()
                .keyHandle(new HsmKeyHandle("recipient-mlkem"))
                .operation(HsmKeyEncapsulationOperation.ENCAPSULATE)
                .build();

        assertThat(request.encapsulatedKey()).isNull();
    }

    @Test
    void build_givenEncapsulateWithEncapsulatedKey_thenThrowsIllegalArgumentException() {
        var builder = HsmKeyEncapsulation.builder()
                .keyHandle(new HsmKeyHandle("recipient-mlkem"))
                .operation(HsmKeyEncapsulationOperation.ENCAPSULATE)
                .encapsulatedKey(ByteSequence.of(new byte[] {1}));

        assertThatThrownBy(builder::build).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void build_givenDecapsulateWithoutEncapsulatedKey_thenThrowsIllegalArgumentException() {
        var builder = HsmKeyEncapsulation.builder()
                .keyHandle(new HsmKeyHandle("own-mlkem"))
                .operation(HsmKeyEncapsulationOperation.DECAPSULATE);

        assertThatThrownBy(builder::build).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void build_givenDecapsulateWithEncapsulatedKey_thenReturnsRequest() {
        var request = HsmKeyEncapsulation.builder()
                .keyHandle(new HsmKeyHandle("own-mlkem"))
                .operation(HsmKeyEncapsulationOperation.DECAPSULATE)
                .encapsulatedKey(ByteSequence.of(new byte[] {1, 2}))
                .build();

        assertThat(request.encapsulatedKey()).isEqualTo(ByteSequence.of(new byte[] {1, 2}));
    }
}
