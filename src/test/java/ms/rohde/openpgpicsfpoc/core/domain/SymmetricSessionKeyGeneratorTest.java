package ms.rohde.openpgpicsfpoc.core.domain;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.security.SecureRandom;
import java.util.Arrays;
import org.junit.jupiter.api.Test;

class SymmetricSessionKeyGeneratorTest {

    @Test
    void generate_givenLength_thenReturnsSequenceOfRequestedLength() {
        var generator = new SymmetricSessionKeyGenerator(new SecureRandom());

        assertThat(generator.generate(32).length()).isEqualTo(32);
    }

    @Test
    void generate_givenFixedRandomSource_thenReturnsDeterministicBytes() {
        var fixedRandom = new SecureRandom() {
            @Override
            public void nextBytes(byte[] bytes) {
                Arrays.fill(bytes, (byte) 7);
            }
        };
        var generator = new SymmetricSessionKeyGenerator(fixedRandom);

        assertThat(generator.generate(4).value()).containsExactly(7, 7, 7, 7);
    }

    @Test
    void generate_givenZeroLength_thenThrowsIllegalArgumentException() {
        var generator = new SymmetricSessionKeyGenerator(new SecureRandom());

        assertThatThrownBy(() -> generator.generate(0)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void constructor_givenNullSecureRandom_thenThrowsNullPointerException() {
        assertThatThrownBy(() -> new SymmetricSessionKeyGenerator(null)).isInstanceOf(NullPointerException.class);
    }
}
