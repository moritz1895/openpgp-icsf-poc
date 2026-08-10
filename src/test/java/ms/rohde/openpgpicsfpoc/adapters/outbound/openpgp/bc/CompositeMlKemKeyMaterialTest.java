package ms.rohde.openpgpicsfpoc.adapters.outbound.openpgp.bc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Arrays;
import ms.rohde.openpgpicsfpoc.core.domain.HsmKeyHandle;
import org.junit.jupiter.api.Test;

class CompositeMlKemKeyMaterialTest {

    @Test
    void compose_thenEcdhAndMlkemPartsRoundTrip() {
        byte[] ecdhPublicKey = fill((byte) 0xAB, CompositeMlKemKeyMaterial.ECDH_PUBLIC_KEY_LENGTH);
        byte[] mlkemPublicKey = fill((byte) 0xCD, CompositeMlKemKeyMaterial.MLKEM_PUBLIC_KEY_LENGTH);

        byte[] composite = CompositeMlKemKeyMaterial.compose(ecdhPublicKey, mlkemPublicKey);

        assertThat(composite).hasSize(
                CompositeMlKemKeyMaterial.ECDH_PUBLIC_KEY_LENGTH + CompositeMlKemKeyMaterial.MLKEM_PUBLIC_KEY_LENGTH);
        assertThat(CompositeMlKemKeyMaterial.ecdhPublicKeyPart(composite)).isEqualTo(ecdhPublicKey);
        assertThat(CompositeMlKemKeyMaterial.mlkemPublicKeyPart(composite)).isEqualTo(mlkemPublicKey);
    }

    @Test
    void compose_givenWrongEcdhLength_thenThrowsIllegalArgumentException() {
        byte[] tooShort = fill((byte) 0x01, 31);
        byte[] mlkemPublicKey = fill((byte) 0xCD, CompositeMlKemKeyMaterial.MLKEM_PUBLIC_KEY_LENGTH);

        assertThatThrownBy(() -> CompositeMlKemKeyMaterial.compose(tooShort, mlkemPublicKey))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void ecdhPublicKeyPart_givenWrongCompositeLength_thenThrowsIllegalArgumentException() {
        byte[] malformed = fill((byte) 0x01, 100);

        assertThatThrownBy(() -> CompositeMlKemKeyMaterial.ecdhPublicKeyPart(malformed))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void ecdhSubKeyHandle_givenPrimaryHandle_thenDerivesDeterministicSuffixedHandle() {
        var primary = new HsmKeyHandle("bob-mlkem768-x25519");

        var derived = CompositeMlKemKeyMaterial.ecdhSubKeyHandle(primary);

        assertThat(derived).isEqualTo(new HsmKeyHandle("bob-mlkem768-x25519-x25519"));
        assertThat(CompositeMlKemKeyMaterial.ecdhSubKeyHandle(primary)).isEqualTo(derived);
    }

    private static byte[] fill(byte value, int length) {
        byte[] result = new byte[length];
        Arrays.fill(result, value);
        return result;
    }
}
