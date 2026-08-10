package ms.rohde.openpgpicsfpoc.core.domain;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

class PgpPublicKeyTest {

    @Test
    void constructor_givenValidMaterial_thenCreatesInstance() {
        var key = new PgpPublicKey(PgpPublicKeyAlgorithm.RSA, ByteSequence.of(new byte[] {1, 2, 3}));

        assertThat(key.algorithm()).isEqualTo(PgpPublicKeyAlgorithm.RSA);
        assertThat(key.encodedKeyMaterial().length()).isEqualTo(3);
    }

    @Test
    void constructor_givenEmptyKeyMaterial_thenThrowsIllegalArgumentException() {
        assertThatThrownBy(() -> new PgpPublicKey(PgpPublicKeyAlgorithm.RSA, ByteSequence.empty()))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void constructor_givenNullAlgorithm_thenThrowsNullPointerException() {
        assertThatThrownBy(() -> new PgpPublicKey(null, ByteSequence.of(new byte[] {1})))
                .isInstanceOf(NullPointerException.class);
    }
}
