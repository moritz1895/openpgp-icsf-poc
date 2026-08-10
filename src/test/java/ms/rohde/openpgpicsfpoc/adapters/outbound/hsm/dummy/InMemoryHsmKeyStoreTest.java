package ms.rohde.openpgpicsfpoc.adapters.outbound.hsm.dummy;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.security.KeyPairGenerator;
import ms.rohde.openpgpicsfpoc.core.domain.HsmKeyHandle;
import org.junit.jupiter.api.Test;

class InMemoryHsmKeyStoreTest {

    @Test
    void requirePublicKey_givenRegisteredKeyPair_thenReturnsPublicKey() throws Exception {
        var store = new InMemoryHsmKeyStore();
        var handle = new HsmKeyHandle("alice");
        var keyPair = KeyPairGenerator.getInstance("X25519").generateKeyPair();
        store.registerKeyPair(handle, keyPair);

        assertThat(store.requirePublicKey(handle)).isEqualTo(keyPair.getPublic());
        assertThat(store.requirePrivateKey(handle)).isEqualTo(keyPair.getPrivate());
    }

    @Test
    void requirePublicKey_givenRegisteredPublicKeyOnly_thenReturnsPublicKey() throws Exception {
        var store = new InMemoryHsmKeyStore();
        var handle = new HsmKeyHandle("bob-imported");
        var keyPair = KeyPairGenerator.getInstance("X25519").generateKeyPair();
        store.registerPublicKey(handle, keyPair.getPublic());

        assertThat(store.requirePublicKey(handle)).isEqualTo(keyPair.getPublic());
    }

    @Test
    void requirePrivateKey_givenPublicKeyOnlyHandle_thenThrowsIllegalStateException() throws Exception {
        var store = new InMemoryHsmKeyStore();
        var handle = new HsmKeyHandle("bob-imported");
        var keyPair = KeyPairGenerator.getInstance("X25519").generateKeyPair();
        store.registerPublicKey(handle, keyPair.getPublic());

        assertThatThrownBy(() -> store.requirePrivateKey(handle)).isInstanceOf(IllegalStateException.class);
    }

    @Test
    void requirePublicKey_givenUnknownHandle_thenThrowsIllegalStateException() {
        var store = new InMemoryHsmKeyStore();

        assertThatThrownBy(() -> store.requirePublicKey(new HsmKeyHandle("unknown")))
                .isInstanceOf(IllegalStateException.class);
    }
}
