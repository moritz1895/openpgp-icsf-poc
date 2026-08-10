package ms.rohde.openpgpicsfpoc.core.domain;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

class ByteSequenceTest {

    @Test
    void of_givenEqualByteArrays_thenSequencesAreEqual() {
        var first = ByteSequence.of(new byte[] {1, 2, 3});
        var second = ByteSequence.of(new byte[] {1, 2, 3});

        assertThat(first).isEqualTo(second);
        assertThat(first.hashCode()).isEqualTo(second.hashCode());
    }

    @Test
    void of_givenDifferentByteArrays_thenSequencesAreNotEqual() {
        var first = ByteSequence.of(new byte[] {1, 2, 3});
        var second = ByteSequence.of(new byte[] {1, 2, 4});

        assertThat(first).isNotEqualTo(second);
    }

    @Test
    void value_givenConstructedSequence_thenReturnsDefensiveCopy() {
        var original = new byte[] {1, 2, 3};
        var sequence = ByteSequence.of(original);
        original[0] = 99;

        assertThat(sequence.value()).containsExactly(1, 2, 3);
    }

    @Test
    void value_givenReturnedArray_thenMutatingItDoesNotAffectSequence() {
        var sequence = ByteSequence.of(new byte[] {1, 2, 3});
        var returned = sequence.value();
        returned[0] = 99;

        assertThat(sequence.value()).containsExactly(1, 2, 3);
    }

    @Test
    void length_givenThreeBytes_thenReturnsThree() {
        assertThat(ByteSequence.of(new byte[] {1, 2, 3}).length()).isEqualTo(3);
    }

    @Test
    void isEmpty_givenEmptySequence_thenReturnsTrue() {
        assertThat(ByteSequence.empty().isEmpty()).isTrue();
    }

    @Test
    void isEmpty_givenNonEmptySequence_thenReturnsFalse() {
        assertThat(ByteSequence.of(new byte[] {1}).isEmpty()).isFalse();
    }

    @Test
    void concat_givenTwoSequences_thenReturnsCombinedSequence() {
        var first = ByteSequence.of(new byte[] {1, 2});
        var second = ByteSequence.of(new byte[] {3, 4});

        assertThat(first.concat(second).value()).containsExactly(1, 2, 3, 4);
    }

    @Test
    void of_givenNullArray_thenThrowsNullPointerException() {
        assertThatThrownBy(() -> ByteSequence.of(null)).isInstanceOf(NullPointerException.class);
    }

    @Test
    void toString_givenAnySequence_thenDoesNotLeakContent() {
        var sequence = ByteSequence.of(new byte[] {10, 20, 30, 40, 90});

        assertThat(sequence.toString()).doesNotContain("10", "20", "30", "40", "90").contains("length=5");
    }
}
