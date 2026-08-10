package ms.rohde.openpgpicsfpoc.core.app;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.then;

import ms.rohde.openpgpicsfpoc.core.domain.ByteSequence;
import ms.rohde.openpgpicsfpoc.core.domain.HsmKeyHandle;
import ms.rohde.openpgpicsfpoc.core.domain.MissingKeyAgreementKeyException;
import ms.rohde.openpgpicsfpoc.core.domain.OpenPgpMessage;
import ms.rohde.openpgpicsfpoc.core.domain.PgpEllipticCurve;
import ms.rohde.openpgpicsfpoc.core.domain.PgpEncryptionProfile;
import ms.rohde.openpgpicsfpoc.core.domain.PgpKeyReference;
import ms.rohde.openpgpicsfpoc.core.domain.PgpPublicKey;
import ms.rohde.openpgpicsfpoc.core.domain.PgpPublicKeyAlgorithm;
import ms.rohde.openpgpicsfpoc.core.domain.UnsupportedEncryptionAlgorithmException;
import ms.rohde.openpgpicsfpoc.ports.outbound.OpenPgpEncryptionRequest;
import ms.rohde.openpgpicsfpoc.ports.outbound.OpenPgpMessageCodec;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class EncryptOpenPgpMessageServiceTest {

    @Mock
    private OpenPgpMessageCodec codec;

    private EncryptOpenPgpMessageService service;

    @BeforeEach
    void setUp() {
        service = new EncryptOpenPgpMessageService(codec);
    }

    private static PgpKeyReference keyReference(String alias, PgpPublicKeyAlgorithm algorithm) {
        return new PgpKeyReference(
                new HsmKeyHandle(alias), new PgpPublicKey(algorithm, ByteSequence.of(new byte[] {1, 2, 3})));
    }

    private static PgpKeyReference ecdhKeyReference(String alias, PgpEllipticCurve curve) {
        return new PgpKeyReference(
                new HsmKeyHandle(alias),
                new PgpPublicKey(PgpPublicKeyAlgorithm.ECDH, ByteSequence.of(new byte[] {1, 2, 3}), curve));
    }

    private static OpenPgpMessage codecResult() {
        return new OpenPgpMessage(ByteSequence.of(new byte[] {9, 9, 9}));
    }

    @Test
    void encrypt_givenRsaRecipient_thenDelegatesToCodecWithoutSenderKey() {
        var recipient = keyReference("bob-rsa", PgpPublicKeyAlgorithm.RSA);
        var command = new EncryptOpenPgpMessageCommand(
                ByteSequence.of("hello".getBytes()), recipient, null, PgpEncryptionProfile.LEGACY_CFB_MDC);
        given(codec.encrypt(any())).willReturn(codecResult());

        var result = service.encrypt(command);

        assertThat(result).isEqualTo(codecResult());
        ArgumentCaptor<OpenPgpEncryptionRequest> captor = ArgumentCaptor.forClass(OpenPgpEncryptionRequest.class);
        then(codec).should().encrypt(captor.capture());
        assertThat(captor.getValue().plaintext()).isEqualTo(ByteSequence.of("hello".getBytes()));
        assertThat(captor.getValue().recipient()).isEqualTo(recipient);
        assertThat(captor.getValue().senderKeyAgreementKey()).isNull();
        assertThat(captor.getValue().profile()).isEqualTo(PgpEncryptionProfile.LEGACY_CFB_MDC);
    }

    @Test
    void encrypt_givenX25519RecipientWithSenderKey_thenDelegatesToCodecWithSenderKey() {
        var recipient = keyReference("bob-x25519", PgpPublicKeyAlgorithm.X25519);
        var sender = keyReference("alice-x25519", PgpPublicKeyAlgorithm.X25519);
        var command = new EncryptOpenPgpMessageCommand(
                ByteSequence.of("hello".getBytes()), recipient, sender, PgpEncryptionProfile.AEAD_V2);
        given(codec.encrypt(any())).willReturn(codecResult());

        var result = service.encrypt(command);

        assertThat(result).isEqualTo(codecResult());
        ArgumentCaptor<OpenPgpEncryptionRequest> captor = ArgumentCaptor.forClass(OpenPgpEncryptionRequest.class);
        then(codec).should().encrypt(captor.capture());
        assertThat(captor.getValue().senderKeyAgreementKey()).isEqualTo(sender);
    }

    @Test
    void encrypt_givenX25519RecipientWithoutSenderKey_thenThrowsMissingKeyAgreementKeyException() {
        var recipient = keyReference("bob-x25519", PgpPublicKeyAlgorithm.X25519);
        var command = new EncryptOpenPgpMessageCommand(
                ByteSequence.of("hello".getBytes()), recipient, null, PgpEncryptionProfile.AEAD_V2);

        assertThatThrownBy(() -> service.encrypt(command)).isInstanceOf(MissingKeyAgreementKeyException.class);
        then(codec).shouldHaveNoInteractions();
    }

    @Test
    void encrypt_givenEcdhRecipientWithSenderKey_thenDelegatesToCodec() {
        var recipient = ecdhKeyReference("bob-p256", PgpEllipticCurve.P256);
        var sender = keyReference("alice-x25519", PgpPublicKeyAlgorithm.X25519);
        var command = new EncryptOpenPgpMessageCommand(
                ByteSequence.of("hello".getBytes()), recipient, sender, PgpEncryptionProfile.LEGACY_CFB_MDC);
        given(codec.encrypt(any())).willReturn(codecResult());

        var result = service.encrypt(command);

        assertThat(result).isEqualTo(codecResult());
        ArgumentCaptor<OpenPgpEncryptionRequest> captor = ArgumentCaptor.forClass(OpenPgpEncryptionRequest.class);
        then(codec).should().encrypt(captor.capture());
        assertThat(captor.getValue().recipient().publicKey().curve()).isEqualTo(PgpEllipticCurve.P256);
    }

    @Test
    void encrypt_givenEcdhRecipientWithoutSenderKey_thenThrowsMissingKeyAgreementKeyException() {
        var recipient = ecdhKeyReference("bob-p384", PgpEllipticCurve.P384);
        var command = new EncryptOpenPgpMessageCommand(
                ByteSequence.of("hello".getBytes()), recipient, null, PgpEncryptionProfile.LEGACY_CFB_MDC);

        assertThatThrownBy(() -> service.encrypt(command)).isInstanceOf(MissingKeyAgreementKeyException.class);
        then(codec).shouldHaveNoInteractions();
    }

    @Test
    void encrypt_givenCompositeRecipientWithSenderKey_thenDelegatesToCodec() {
        var recipient = keyReference("bob-mlkem", PgpPublicKeyAlgorithm.ML_KEM_768_X25519);
        var sender = keyReference("alice-x25519", PgpPublicKeyAlgorithm.X25519);
        var command = new EncryptOpenPgpMessageCommand(
                ByteSequence.of("hello".getBytes()), recipient, sender, PgpEncryptionProfile.AEAD_V2);
        given(codec.encrypt(any())).willReturn(codecResult());

        var result = service.encrypt(command);

        assertThat(result).isEqualTo(codecResult());
        then(codec).should().encrypt(any());
    }

    @Test
    void encrypt_givenCompositeRecipientWithoutSenderKey_thenThrowsMissingKeyAgreementKeyException() {
        var recipient = keyReference("bob-mlkem", PgpPublicKeyAlgorithm.ML_KEM_768_X25519);
        var command = new EncryptOpenPgpMessageCommand(
                ByteSequence.of("hello".getBytes()), recipient, null, PgpEncryptionProfile.AEAD_V2);

        assertThatThrownBy(() -> service.encrypt(command)).isInstanceOf(MissingKeyAgreementKeyException.class);
        then(codec).shouldHaveNoInteractions();
    }

    @Test
    void encrypt_givenSignatureOnlyAlgorithm_thenThrowsUnsupportedEncryptionAlgorithmException() {
        var recipient = keyReference("bob-ecdsa", PgpPublicKeyAlgorithm.ECDSA);
        var command = new EncryptOpenPgpMessageCommand(
                ByteSequence.of("hello".getBytes()), recipient, null, PgpEncryptionProfile.LEGACY_CFB_MDC);

        assertThatThrownBy(() -> service.encrypt(command))
                .isInstanceOf(UnsupportedEncryptionAlgorithmException.class);
        then(codec).shouldHaveNoInteractions();
    }
}
