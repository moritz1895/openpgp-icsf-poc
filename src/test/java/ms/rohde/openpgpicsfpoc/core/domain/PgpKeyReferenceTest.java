package ms.rohde.openpgpicsfpoc.core.domain;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

class PgpKeyReferenceTest {

    private static PgpPublicKey rsaPublicKey() {
        return new PgpPublicKey(PgpPublicKeyAlgorithm.RSA, ByteSequence.of(new byte[] {1, 2, 3}));
    }

    @Test
    void equals_givenSameKeyHandleDifferentPublicKey_thenReferencesAreEqual() {
        var handle = new HsmKeyHandle("alice-rsa");
        var first = new PgpKeyReference(handle, rsaPublicKey());
        var second = new PgpKeyReference(handle,
                new PgpPublicKey(PgpPublicKeyAlgorithm.RSA, ByteSequence.of(new byte[] {9, 9})));

        assertThat(first).isEqualTo(second);
        assertThat(first.hashCode()).isEqualTo(second.hashCode());
    }

    @Test
    void equals_givenDifferentKeyHandle_thenReferencesAreNotEqual() {
        var first = new PgpKeyReference(new HsmKeyHandle("alice-rsa"), rsaPublicKey());
        var second = new PgpKeyReference(new HsmKeyHandle("bob-rsa"), rsaPublicKey());

        assertThat(first).isNotEqualTo(second);
    }

    @Test
    void constructor_givenNullKeyHandle_thenThrowsNullPointerException() {
        assertThatThrownBy(() -> new PgpKeyReference(null, rsaPublicKey()))
                .isInstanceOf(NullPointerException.class);
    }
}
