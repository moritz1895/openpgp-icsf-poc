package ms.rohde.openpgpicsfpoc.adapters.outbound.hsm.dummy;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.security.KeyPairGenerator;
import java.security.Signature;
import ms.rohde.openpgpicsfpoc.core.domain.ByteSequence;
import ms.rohde.openpgpicsfpoc.core.domain.HsmKeyHandle;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmSignature;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmSignatureAlgorithm;
import org.junit.jupiter.api.Test;

class DummyHsmSignatureExecutorTest {

    @Test
    void execute_givenEddsaSigner_thenProducesVerifiableSignature() throws Exception {
        var keyStore = new InMemoryHsmKeyStore();
        var handle = new HsmKeyHandle("signer-eddsa");
        var keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        keyStore.registerKeyPair(handle, keyPair);
        var executor = new DummyHsmSignatureExecutor(keyStore);
        var digest = ByteSequence.of(new byte[32]);

        var result = executor.execute(HsmSignature.builder()
                .keyHandle(handle)
                .algorithm(HsmSignatureAlgorithm.EDDSA)
                .digest(digest)
                .build());

        var verifier = Signature.getInstance("Ed25519");
        verifier.initVerify(keyPair.getPublic());
        verifier.update(digest.value());
        assertThat(verifier.verify(result.signature().value())).isTrue();
    }

    @Test
    void execute_givenRsaSigner_thenProducesVerifiableSignature() throws Exception {
        var keyStore = new InMemoryHsmKeyStore();
        var handle = new HsmKeyHandle("signer-rsa");
        var keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        var keyPair = keyPairGenerator.generateKeyPair();
        keyStore.registerKeyPair(handle, keyPair);
        var executor = new DummyHsmSignatureExecutor(keyStore);
        var digest = ByteSequence.of(new byte[32]);

        var result = executor.execute(HsmSignature.builder()
                .keyHandle(handle)
                .algorithm(HsmSignatureAlgorithm.RSA_PKCS1V15)
                .digest(digest)
                .build());

        var verifier = Signature.getInstance("NONEwithRSA");
        verifier.initVerify(keyPair.getPublic());
        verifier.update(digest.value());
        assertThat(verifier.verify(result.signature().value())).isTrue();
    }

    @Test
    void execute_givenUnknownHandle_thenThrowsIllegalStateException() {
        var executor = new DummyHsmSignatureExecutor(new InMemoryHsmKeyStore());
        var request = HsmSignature.builder()
                .keyHandle(new HsmKeyHandle("unknown"))
                .algorithm(HsmSignatureAlgorithm.EDDSA)
                .digest(ByteSequence.of(new byte[32]))
                .build();

        assertThatThrownBy(() -> executor.execute(request)).isInstanceOf(IllegalStateException.class);
    }
}
