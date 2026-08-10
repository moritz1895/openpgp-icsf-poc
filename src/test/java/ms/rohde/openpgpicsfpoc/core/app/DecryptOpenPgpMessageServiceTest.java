package ms.rohde.openpgpicsfpoc.core.app;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.then;

import ms.rohde.openpgpicsfpoc.core.domain.ByteSequence;
import ms.rohde.openpgpicsfpoc.core.domain.HsmKeyHandle;
import ms.rohde.openpgpicsfpoc.core.domain.OpenPgpMessage;
import ms.rohde.openpgpicsfpoc.core.domain.PgpKeyReference;
import ms.rohde.openpgpicsfpoc.core.domain.PgpPublicKey;
import ms.rohde.openpgpicsfpoc.core.domain.PgpPublicKeyAlgorithm;
import ms.rohde.openpgpicsfpoc.ports.outbound.OpenPgpDecryptionRequest;
import ms.rohde.openpgpicsfpoc.ports.outbound.OpenPgpMessageCodec;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class DecryptOpenPgpMessageServiceTest {

    @Mock
    private OpenPgpMessageCodec codec;

    private DecryptOpenPgpMessageService service;

    @BeforeEach
    void setUp() {
        service = new DecryptOpenPgpMessageService(codec);
    }

    private static PgpKeyReference keyReference(String alias, PgpPublicKeyAlgorithm algorithm) {
        return new PgpKeyReference(
                new HsmKeyHandle(alias), new PgpPublicKey(algorithm, ByteSequence.of(new byte[] {1, 2, 3})));
    }

    private static OpenPgpMessage message() {
        return new OpenPgpMessage(ByteSequence.of(new byte[] {9, 9, 9}));
    }

    @Test
    void decrypt_givenValidCommand_thenDelegatesToCodecAndReturnsPlaintext() {
        var recipient = keyReference("bob-rsa", PgpPublicKeyAlgorithm.RSA);
        var command = new DecryptOpenPgpMessageCommand(message(), recipient);
        given(codec.decrypt(any())).willReturn(ByteSequence.of("plain".getBytes()));

        var plaintext = service.decrypt(command);

        assertThat(plaintext).isEqualTo(ByteSequence.of("plain".getBytes()));
        ArgumentCaptor<OpenPgpDecryptionRequest> captor = ArgumentCaptor.forClass(OpenPgpDecryptionRequest.class);
        then(codec).should().decrypt(captor.capture());
        assertThat(captor.getValue().message()).isEqualTo(message());
        assertThat(captor.getValue().recipient()).isEqualTo(recipient);
    }
}
