package ms.rohde.openpgpicsfpoc.core.app;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.then;

import java.security.SecureRandom;
import java.util.Arrays;
import ms.rohde.openpgpicsfpoc.core.domain.ByteSequence;
import ms.rohde.openpgpicsfpoc.core.domain.HsmKeyHandle;
import ms.rohde.openpgpicsfpoc.core.domain.HybridSharedSecretCombiner;
import ms.rohde.openpgpicsfpoc.core.domain.MissingKeyAgreementKeyException;
import ms.rohde.openpgpicsfpoc.core.domain.OpenPgpMessage;
import ms.rohde.openpgpicsfpoc.core.domain.PgpEncryptionProfile;
import ms.rohde.openpgpicsfpoc.core.domain.PgpKeyReference;
import ms.rohde.openpgpicsfpoc.core.domain.PgpPublicKey;
import ms.rohde.openpgpicsfpoc.core.domain.PgpPublicKeyAlgorithm;
import ms.rohde.openpgpicsfpoc.core.domain.SymmetricSessionKeyGenerator;
import ms.rohde.openpgpicsfpoc.core.domain.UnsupportedEncryptionAlgorithmException;
import ms.rohde.openpgpicsfpoc.ports.outbound.OpenPgpEncryptionFramingRequest;
import ms.rohde.openpgpicsfpoc.ports.outbound.OpenPgpMessageCodec;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmAesEncryptionExecutor;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmAesEncryptionResult;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmKeyAgreementExecutor;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmKeyAgreementResult;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmKeyEncapsulationExecutor;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmKeyEncapsulationResult;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmRsaEncryptionExecutor;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmRsaEncryptionResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class EncryptOpenPgpMessageServiceTest {

    @Mock
    private HsmRsaEncryptionExecutor rsaExecutor;

    @Mock
    private HsmAesEncryptionExecutor aesExecutor;

    @Mock
    private HsmKeyAgreementExecutor keyAgreementExecutor;

    @Mock
    private HsmKeyEncapsulationExecutor keyEncapsulationExecutor;

    @Mock
    private OpenPgpMessageCodec codec;

    private EncryptOpenPgpMessageService service;

    @BeforeEach
    void setUp() {
        var fixedRandom = new SecureRandom() {
            @Override
            public void nextBytes(byte[] bytes) {
                Arrays.fill(bytes, (byte) 7);
            }
        };
        service = new EncryptOpenPgpMessageService(
                rsaExecutor,
                aesExecutor,
                keyAgreementExecutor,
                keyEncapsulationExecutor,
                codec,
                new SymmetricSessionKeyGenerator(fixedRandom),
                new HybridSharedSecretCombiner());
    }

    private static PgpKeyReference keyReference(String alias, PgpPublicKeyAlgorithm algorithm) {
        return new PgpKeyReference(
                new HsmKeyHandle(alias), new PgpPublicKey(algorithm, ByteSequence.of(new byte[] {1, 2, 3})));
    }

    private static OpenPgpMessage codecResult() {
        return new OpenPgpMessage(ByteSequence.of(new byte[] {9, 9, 9}));
    }

    @Test
    void encrypt_givenRsaRecipient_thenWrapsSessionKeyViaRsaExecutor() {
        var recipient = keyReference("bob-rsa", PgpPublicKeyAlgorithm.RSA);
        var command = new EncryptOpenPgpMessageCommand(
                ByteSequence.of("hello".getBytes()), recipient, null, PgpEncryptionProfile.LEGACY_CFB_MDC);
        given(rsaExecutor.execute(any())).willReturn(new HsmRsaEncryptionResult(ByteSequence.of(new byte[] {5, 5})));
        given(aesExecutor.execute(any()))
                .willReturn(new HsmAesEncryptionResult(ByteSequence.of(new byte[] {6, 6}), null));
        given(codec.frameEncryptedMessage(any())).willReturn(codecResult());

        var result = service.encrypt(command);

        assertThat(result).isEqualTo(codecResult());
        then(rsaExecutor).should().execute(any());
        then(keyAgreementExecutor).shouldHaveNoInteractions();
        then(keyEncapsulationExecutor).shouldHaveNoInteractions();

        ArgumentCaptor<OpenPgpEncryptionFramingRequest> captor =
                ArgumentCaptor.forClass(OpenPgpEncryptionFramingRequest.class);
        then(codec).should().frameEncryptedMessage(captor.capture());
        assertThat(captor.getValue().wrappedSessionKey()).isEqualTo(ByteSequence.of(new byte[] {5, 5}));
        assertThat(captor.getValue().encapsulatedKey()).isNull();
        assertThat(captor.getValue().algorithm()).isEqualTo(PgpPublicKeyAlgorithm.RSA);
    }

    @Test
    void encrypt_givenX25519RecipientWithSenderKey_thenDerivesSessionKeyViaKeyAgreement() {
        var recipient = keyReference("bob-x25519", PgpPublicKeyAlgorithm.X25519);
        var sender = keyReference("alice-x25519", PgpPublicKeyAlgorithm.X25519);
        var command = new EncryptOpenPgpMessageCommand(
                ByteSequence.of("hello".getBytes()), recipient, sender, PgpEncryptionProfile.AEAD_V2);
        given(keyAgreementExecutor.execute(any()))
                .willReturn(new HsmKeyAgreementResult(ByteSequence.of(new byte[] {4, 4})));
        given(aesExecutor.execute(any()))
                .willReturn(new HsmAesEncryptionResult(ByteSequence.of(new byte[] {6, 6}), ByteSequence.of(new byte[] {7})));
        given(codec.frameEncryptedMessage(any())).willReturn(codecResult());

        var result = service.encrypt(command);

        assertThat(result).isEqualTo(codecResult());
        then(rsaExecutor).shouldHaveNoInteractions();
        then(keyEncapsulationExecutor).shouldHaveNoInteractions();
        then(keyAgreementExecutor).should().execute(any());
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
    void encrypt_givenCompositeRecipient_thenCombinesKeyAgreementAndEncapsulationResults() {
        var recipient = keyReference("bob-mlkem", PgpPublicKeyAlgorithm.ML_KEM_768_X25519);
        var sender = keyReference("alice-x25519", PgpPublicKeyAlgorithm.X25519);
        var command = new EncryptOpenPgpMessageCommand(
                ByteSequence.of("hello".getBytes()), recipient, sender, PgpEncryptionProfile.AEAD_V2);
        given(keyAgreementExecutor.execute(any()))
                .willReturn(new HsmKeyAgreementResult(ByteSequence.of(new byte[] {4, 4})));
        given(keyEncapsulationExecutor.execute(any()))
                .willReturn(new HsmKeyEncapsulationResult(
                        ByteSequence.of(new byte[] {8, 8}), ByteSequence.of(new byte[] {3, 3, 3})));
        given(aesExecutor.execute(any()))
                .willReturn(new HsmAesEncryptionResult(ByteSequence.of(new byte[] {6, 6}), ByteSequence.of(new byte[] {7})));
        given(codec.frameEncryptedMessage(any())).willReturn(codecResult());

        service.encrypt(command);

        then(rsaExecutor).shouldHaveNoInteractions();
        then(keyAgreementExecutor).should().execute(any());
        then(keyEncapsulationExecutor).should().execute(any());

        ArgumentCaptor<OpenPgpEncryptionFramingRequest> captor =
                ArgumentCaptor.forClass(OpenPgpEncryptionFramingRequest.class);
        then(codec).should().frameEncryptedMessage(captor.capture());
        assertThat(captor.getValue().encapsulatedKey()).isEqualTo(ByteSequence.of(new byte[] {3, 3, 3}));
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
