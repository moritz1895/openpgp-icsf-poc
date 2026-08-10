package ms.rohde.openpgpicsfpoc.core.domain;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

class HsmKeyHandleTest {

    @Test
    void constructor_givenEqualAlias_thenHandlesAreEqual() {
        assertThat(new HsmKeyHandle("recipient-rsa-1")).isEqualTo(new HsmKeyHandle("recipient-rsa-1"));
    }

    @Test
    void constructor_givenNullAlias_thenThrowsNullPointerException() {
        assertThatThrownBy(() -> new HsmKeyHandle(null)).isInstanceOf(NullPointerException.class);
    }

    @Test
    void constructor_givenBlankAlias_thenThrowsIllegalArgumentException() {
        assertThatThrownBy(() -> new HsmKeyHandle("   ")).isInstanceOf(IllegalArgumentException.class);
    }
}
