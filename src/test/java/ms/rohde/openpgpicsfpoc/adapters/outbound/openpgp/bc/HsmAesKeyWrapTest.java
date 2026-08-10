package ms.rohde.openpgpicsfpoc.adapters.outbound.openpgp.bc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.security.SecureRandom;
import ms.rohde.openpgpicsfpoc.adapters.outbound.hsm.dummy.DummyHsmAesEncryptionExecutor;
import org.junit.jupiter.api.Test;

class HsmAesKeyWrapTest {

    private final DummyHsmAesEncryptionExecutor executor = new DummyHsmAesEncryptionExecutor();

    @Test
    void wrapThenUnwrap_givenAes256SessionKey_thenRecoversOriginalBytes() {
        byte[] kek = randomBytes(32);
        byte[] plaintext = randomBytes(32);
        var wrap = new HsmAesKeyWrap(executor, kek);

        byte[] wrapped = wrap.wrap(plaintext);
        byte[] recovered = wrap.unwrap(wrapped);

        assertThat(wrapped).hasSize(plaintext.length + 8);
        assertThat(recovered).isEqualTo(plaintext);
    }

    @Test
    void wrapThenUnwrap_givenPaddedSessionInfo_thenRecoversOriginalBytes() {
        byte[] kek = randomBytes(16);
        byte[] plaintext = randomBytes(40);
        var wrap = new HsmAesKeyWrap(executor, kek);

        byte[] wrapped = wrap.wrap(plaintext);
        byte[] recovered = wrap.unwrap(wrapped);

        assertThat(recovered).isEqualTo(plaintext);
    }

    @Test
    void unwrap_givenWrongKek_thenThrowsIntegrityException() {
        byte[] plaintext = randomBytes(32);
        byte[] wrapped = new HsmAesKeyWrap(executor, randomBytes(32)).wrap(plaintext);

        assertThatThrownBy(() -> new HsmAesKeyWrap(executor, randomBytes(32)).unwrap(wrapped))
                .isInstanceOf(HsmAesKeyUnwrapIntegrityException.class);
    }

    private static byte[] randomBytes(int length) {
        byte[] bytes = new byte[length];
        new SecureRandom().nextBytes(bytes);
        return bytes;
    }
}
