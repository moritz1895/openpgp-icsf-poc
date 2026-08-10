package ms.rohde.openpgpicsfpoc.core.app;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.then;

import ms.rohde.openpgpicsfpoc.core.domain.ByteSequence;
import ms.rohde.openpgpicsfpoc.core.domain.OpenPgpMessage;
import ms.rohde.openpgpicsfpoc.core.domain.PgpPublicKey;
import ms.rohde.openpgpicsfpoc.core.domain.PgpPublicKeyAlgorithm;
import ms.rohde.openpgpicsfpoc.ports.outbound.OpenPgpMessageCodec;
import ms.rohde.openpgpicsfpoc.ports.outbound.OpenPgpVerificationRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class VerifyOpenPgpSignatureServiceTest {

    @Mock
    private OpenPgpMessageCodec codec;

    private VerifyOpenPgpSignatureService service;

    @BeforeEach
    void setUp() {
        service = new VerifyOpenPgpSignatureService(codec);
    }

    @Test
    void verify_givenValidSignature_thenDelegatesToCodecAndReturnsTrue() {
        var signedMessage = new OpenPgpMessage(ByteSequence.of(new byte[] {1, 2}));
        var signerPublicKey = new PgpPublicKey(PgpPublicKeyAlgorithm.EDDSA, ByteSequence.of(new byte[] {3, 4}));
        var command = new VerifyOpenPgpSignatureCommand(signedMessage, signerPublicKey);
        given(codec.verifySignedMessage(any())).willReturn(true);

        assertThat(service.verify(command)).isTrue();

        ArgumentCaptor<OpenPgpVerificationRequest> captor = ArgumentCaptor.forClass(OpenPgpVerificationRequest.class);
        then(codec).should().verifySignedMessage(captor.capture());
        assertThat(captor.getValue().signedMessage()).isEqualTo(signedMessage);
        assertThat(captor.getValue().signerPublicKey()).isEqualTo(signerPublicKey);
    }

    @Test
    void verify_givenInvalidSignature_thenReturnsFalse() {
        var command = new VerifyOpenPgpSignatureCommand(
                new OpenPgpMessage(ByteSequence.of(new byte[] {1})),
                new PgpPublicKey(PgpPublicKeyAlgorithm.RSA, ByteSequence.of(new byte[] {2})));
        given(codec.verifySignedMessage(any())).willReturn(false);

        assertThat(service.verify(command)).isFalse();
    }
}
