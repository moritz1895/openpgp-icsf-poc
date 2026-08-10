package ms.rohde.openpgpicsfpoc.adapters.outbound.openpgp.bc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.then;

import ms.rohde.openpgpicsfpoc.core.domain.ByteSequence;
import ms.rohde.openpgpicsfpoc.core.domain.HsmKeyHandle;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmSignatureAlgorithm;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmSignatureExecutor;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmSignatureRequest;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmSignatureResult;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class HsmBackedPGPContentSignerBuilderTest {

    @Mock
    private HsmSignatureExecutor executor;

    private HsmKeyHandle keyHandle;

    @BeforeEach
    void setUp() {
        keyHandle = new HsmKeyHandle("signer-key");
    }

    @Test
    void getSignature_givenRsaAlgorithm_thenSendsPkcs1DigestInfoToHsm() throws Exception {
        given(executor.execute(any())).willReturn(new HsmSignatureResult(ByteSequence.of(new byte[] {9, 9})));
        var builder = new HsmBackedPGPContentSignerBuilder(PublicKeyAlgorithmTags.RSA_GENERAL, executor, keyHandle, 42L);
        var signer = builder.build(0x00, null);
        signer.getOutputStream().write("hello world".getBytes());

        byte[] signature = signer.getSignature();

        assertThat(signature).isEqualTo(new byte[] {9, 9});
        ArgumentCaptor<HsmSignatureRequest> captor = ArgumentCaptor.forClass(HsmSignatureRequest.class);
        then(executor).should().execute(captor.capture());
        var request = captor.getValue();
        assertThat(request.keyHandle()).isEqualTo(keyHandle);
        assertThat(request.algorithm()).isEqualTo(HsmSignatureAlgorithm.RSA_PKCS1V15);
        // DigestInfo-Praefix (19 Byte) + SHA-256-Digest (32 Byte)
        assertThat(request.digest().length()).isEqualTo(51);
    }

    @Test
    void getSignature_givenEcdsaAlgorithm_thenSendsRawDigestToHsm() throws Exception {
        given(executor.execute(any())).willReturn(new HsmSignatureResult(ByteSequence.of(new byte[] {1})));
        var builder = new HsmBackedPGPContentSignerBuilder(PublicKeyAlgorithmTags.ECDSA, executor, keyHandle, 7L);
        var signer = builder.build(0x00, null);

        signer.getSignature();

        ArgumentCaptor<HsmSignatureRequest> captor = ArgumentCaptor.forClass(HsmSignatureRequest.class);
        then(executor).should().execute(captor.capture());
        assertThat(captor.getValue().algorithm()).isEqualTo(HsmSignatureAlgorithm.ECDSA);
        assertThat(captor.getValue().digest().length()).isEqualTo(32);
    }

    @Test
    void getSignatureAndGetDigest_thenReturnConsistentDigestAcrossCalls() throws Exception {
        given(executor.execute(any())).willReturn(new HsmSignatureResult(ByteSequence.of(new byte[] {1})));
        var builder = new HsmBackedPGPContentSignerBuilder(PublicKeyAlgorithmTags.Ed25519, executor, keyHandle, 1L);
        var signer = builder.build(0x00, null);

        signer.getSignature();
        byte[] digest = signer.getDigest();

        ArgumentCaptor<HsmSignatureRequest> captor = ArgumentCaptor.forClass(HsmSignatureRequest.class);
        then(executor).should().execute(captor.capture());
        assertThat(digest).isEqualTo(captor.getValue().digest().value());
    }
}
