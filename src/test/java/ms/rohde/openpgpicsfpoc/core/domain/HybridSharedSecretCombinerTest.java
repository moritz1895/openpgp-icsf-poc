package ms.rohde.openpgpicsfpoc.core.domain;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class HybridSharedSecretCombinerTest {

    private final HybridSharedSecretCombiner combiner = new HybridSharedSecretCombiner();

    @Test
    void combine_givenTwoSecrets_thenReturnsThirtyTwoByteResult() {
        var classical = ByteSequence.of(new byte[] {1, 2, 3});
        var postQuantum = ByteSequence.of(new byte[] {4, 5, 6});

        assertThat(combiner.combine(classical, postQuantum).length()).isEqualTo(32);
    }

    @Test
    void combine_givenSameInputsTwice_thenReturnsSameResult() {
        var classical = ByteSequence.of(new byte[] {1, 2, 3});
        var postQuantum = ByteSequence.of(new byte[] {4, 5, 6});

        assertThat(combiner.combine(classical, postQuantum)).isEqualTo(combiner.combine(classical, postQuantum));
    }

    @Test
    void combine_givenSwappedInputs_thenReturnsDifferentResult() {
        var first = ByteSequence.of(new byte[] {1, 2, 3});
        var second = ByteSequence.of(new byte[] {4, 5, 6});

        assertThat(combiner.combine(first, second)).isNotEqualTo(combiner.combine(second, first));
    }
}
