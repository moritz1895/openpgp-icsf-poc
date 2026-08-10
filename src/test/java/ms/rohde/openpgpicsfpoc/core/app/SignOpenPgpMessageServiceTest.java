package ms.rohde.openpgpicsfpoc.core.app;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.then;

import ms.rohde.openpgpicsfpoc.core.domain.ByteSequence;
import ms.rohde.openpgpicsfpoc.core.domain.HsmKeyHandle;
import ms.rohde.openpgpicsfpoc.core.domain.MessageDigestCalculator;
import ms.rohde.openpgpicsfpoc.core.domain.OpenPgpMessage;
import ms.rohde.openpgpicsfpoc.core.domain.PgpKeyReference;
import ms.rohde.openpgpicsfpoc.core.domain.PgpPublicKey;
import ms.rohde.openpgpicsfpoc.core.domain.PgpPublicKeyAlgorithm;
import ms.rohde.openpgpicsfpoc.core.domain.UnsupportedSigningAlgorithmException;
import ms.rohde.openpgpicsfpoc.ports.outbound.OpenPgpMessageCodec;
import ms.rohde.openpgpicsfpoc.ports.outbound.OpenPgpSigningFramingRequest;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmSignatureExecutor;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmSignatureResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class SignOpenPgpMessageServiceTest {

    @Mock
    private HsmSignatureExecutor signatureExecutor;

    @Mock
    private OpenPgpMessageCodec codec;

    private SignOpenPgpMessageService service;

    @BeforeEach
    void setUp() {
        service = new SignOpenPgpMessageService(signatureExecutor, codec, new MessageDigestCalculator());
    }

    private static PgpKeyReference keyReference(String alias, PgpPublicKeyAlgorithm algorithm) {
        return new PgpKeyReference(
                new HsmKeyHandle(alias), new PgpPublicKey(algorithm, ByteSequence.of(new byte[] {1, 2, 3})));
    }

    @Test
    void sign_givenEddsaSigner_thenSignsLocallyComputedDigest() {
        var signer = keyReference("alice-eddsa", PgpPublicKeyAlgorithm.EDDSA);
        var command = new SignOpenPgpMessageCommand(ByteSequence.of("hello".getBytes()), signer);
        given(signatureExecutor.execute(any()))
                .willReturn(new HsmSignatureResult(ByteSequence.of(new byte[] {9, 9})));
        var codecResult = new OpenPgpMessage(ByteSequence.of(new byte[] {1, 1}));
        given(codec.frameSignedMessage(any())).willReturn(codecResult);

        var result = service.sign(command);

        assertThat(result).isEqualTo(codecResult);
        ArgumentCaptor<OpenPgpSigningFramingRequest> captor = ArgumentCaptor.forClass(OpenPgpSigningFramingRequest.class);
        then(codec).should().frameSignedMessage(captor.capture());
        assertThat(captor.getValue().signature()).isEqualTo(ByteSequence.of(new byte[] {9, 9}));
        assertThat(captor.getValue().digest().length()).isEqualTo(32);
    }

    @Test
    void sign_givenEncryptionOnlyAlgorithm_thenThrowsUnsupportedSigningAlgorithmException() {
        var signer = keyReference("bob-x25519", PgpPublicKeyAlgorithm.X25519);
        var command = new SignOpenPgpMessageCommand(ByteSequence.of("hello".getBytes()), signer);

        assertThatThrownBy(() -> service.sign(command)).isInstanceOf(UnsupportedSigningAlgorithmException.class);
        then(signatureExecutor).shouldHaveNoInteractions();
        then(codec).shouldHaveNoInteractions();
    }
}
