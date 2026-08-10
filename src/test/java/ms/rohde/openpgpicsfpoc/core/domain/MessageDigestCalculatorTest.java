package ms.rohde.openpgpicsfpoc.core.domain;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class MessageDigestCalculatorTest {

    private final MessageDigestCalculator calculator = new MessageDigestCalculator();

    @Test
    void sha256_givenMessage_thenReturnsThirtyTwoByteDigest() {
        var digest = calculator.sha256(ByteSequence.of("hello world".getBytes()));

        assertThat(digest.length()).isEqualTo(32);
    }

    @Test
    void sha256_givenSameMessageTwice_thenReturnsSameDigest() {
        var message = ByteSequence.of("hello world".getBytes());

        assertThat(calculator.sha256(message)).isEqualTo(calculator.sha256(message));
    }

    @Test
    void sha256_givenDifferentMessages_thenReturnsDifferentDigests() {
        var first = calculator.sha256(ByteSequence.of("hello".getBytes()));
        var second = calculator.sha256(ByteSequence.of("world".getBytes()));

        assertThat(first).isNotEqualTo(second);
    }
}
