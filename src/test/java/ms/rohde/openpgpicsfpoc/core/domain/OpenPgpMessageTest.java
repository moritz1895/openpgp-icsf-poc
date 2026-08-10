package ms.rohde.openpgpicsfpoc.core.domain;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

class OpenPgpMessageTest {

    @Test
    void constructor_givenNonEmptyBytes_thenCreatesInstance() {
        var message = new OpenPgpMessage(ByteSequence.of(new byte[] {1, 2, 3}));

        assertThat(message.encoded().length()).isEqualTo(3);
    }

    @Test
    void constructor_givenEmptyBytes_thenThrowsIllegalArgumentException() {
        assertThatThrownBy(() -> new OpenPgpMessage(ByteSequence.empty()))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
