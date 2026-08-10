package ms.rohde.openpgpicsfpoc.adapters.outbound.hsm.dummy;

import static org.assertj.core.api.Assertions.assertThat;

import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import ms.rohde.openpgpicsfpoc.core.domain.HsmKeyHandle;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmEllipticCurve;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmKeyAgreement;
import org.junit.jupiter.api.Test;

class DummyHsmKeyAgreementExecutorTest {

    @Test
    void execute_givenX25519KeyPairsOnBothSides_thenBothSidesDeriveSameSharedSecret() throws Exception {
        var keyStore = new InMemoryHsmKeyStore();
        var aliceHandle = new HsmKeyHandle("alice-x25519");
        var bobHandle = new HsmKeyHandle("bob-x25519");
        var keyPairGenerator = KeyPairGenerator.getInstance("X25519");
        var aliceKeyPair = keyPairGenerator.generateKeyPair();
        var bobKeyPair = keyPairGenerator.generateKeyPair();
        keyStore.registerKeyPair(aliceHandle, aliceKeyPair);
        keyStore.registerKeyPair(bobHandle, bobKeyPair);
        var executor = new DummyHsmKeyAgreementExecutor(keyStore);

        var aliceView = executor.execute(HsmKeyAgreement.builder()
                .curve(HsmEllipticCurve.X25519)
                .localKeyHandle(aliceHandle)
                .peerKeyHandle(bobHandle)
                .build());
        var bobView = executor.execute(HsmKeyAgreement.builder()
                .curve(HsmEllipticCurve.X25519)
                .localKeyHandle(bobHandle)
                .peerKeyHandle(aliceHandle)
                .build());

        assertThat(aliceView.sharedSecret()).isEqualTo(bobView.sharedSecret());
    }

    @Test
    void execute_givenP256KeyPairsOnBothSides_thenBothSidesDeriveSameSharedSecret() throws Exception {
        var keyStore = new InMemoryHsmKeyStore();
        var aliceHandle = new HsmKeyHandle("alice-p256");
        var bobHandle = new HsmKeyHandle("bob-p256");
        var keyPairGenerator = KeyPairGenerator.getInstance("EC");
        keyPairGenerator.initialize(new ECGenParameterSpec("secp256r1"));
        var aliceKeyPair = keyPairGenerator.generateKeyPair();
        var bobKeyPair = keyPairGenerator.generateKeyPair();
        keyStore.registerKeyPair(aliceHandle, aliceKeyPair);
        keyStore.registerKeyPair(bobHandle, bobKeyPair);
        var executor = new DummyHsmKeyAgreementExecutor(keyStore);

        var aliceView = executor.execute(HsmKeyAgreement.builder()
                .curve(HsmEllipticCurve.P256)
                .localKeyHandle(aliceHandle)
                .peerKeyHandle(bobHandle)
                .build());
        var bobView = executor.execute(HsmKeyAgreement.builder()
                .curve(HsmEllipticCurve.P256)
                .localKeyHandle(bobHandle)
                .peerKeyHandle(aliceHandle)
                .build());

        assertThat(aliceView.sharedSecret()).isEqualTo(bobView.sharedSecret());
    }
}
