package ms.rohde.openpgpicsfpoc.core.app;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.then;

import ms.rohde.openpgpicsfpoc.core.domain.ByteSequence;
import ms.rohde.openpgpicsfpoc.core.domain.HsmKeyHandle;
import ms.rohde.openpgpicsfpoc.core.domain.HybridSharedSecretCombiner;
import ms.rohde.openpgpicsfpoc.core.domain.OpenPgpMessage;
import ms.rohde.openpgpicsfpoc.core.domain.PgpKeyReference;
import ms.rohde.openpgpicsfpoc.core.domain.PgpPublicKey;
import ms.rohde.openpgpicsfpoc.core.domain.PgpPublicKeyAlgorithm;
import ms.rohde.openpgpicsfpoc.ports.outbound.OpenPgpEncryptionFramingContext;
import ms.rohde.openpgpicsfpoc.ports.outbound.OpenPgpMessageCodec;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmAesCipherMode;
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
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class DecryptOpenPgpMessageServiceTest {

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

    private DecryptOpenPgpMessageService service;

    @BeforeEach
    void setUp() {
        service = new DecryptOpenPgpMessageService(
                rsaExecutor, aesExecutor, keyAgreementExecutor, keyEncapsulationExecutor, codec,
                new HybridSharedSecretCombiner());
    }

    private static PgpKeyReference keyReference(String alias, PgpPublicKeyAlgorithm algorithm) {
        return new PgpKeyReference(
                new HsmKeyHandle(alias), new PgpPublicKey(algorithm, ByteSequence.of(new byte[] {1, 2, 3})));
    }

    private static OpenPgpMessage message() {
        return new OpenPgpMessage(ByteSequence.of(new byte[] {9, 9, 9}));
    }

    @Test
    void decrypt_givenRsaContext_thenUnwrapsSessionKeyViaRsaExecutor() {
        var recipient = keyReference("bob-rsa", PgpPublicKeyAlgorithm.RSA);
        var command = new DecryptOpenPgpMessageCommand(message(), recipient);
        var context = new OpenPgpEncryptionFramingContext(
                PgpPublicKeyAlgorithm.RSA,
                HsmAesCipherMode.CFB,
                ByteSequence.of(new byte[] {5, 5}),
                null,
                null,
                ByteSequence.of(new byte[] {6, 6}),
                ByteSequence.of(new byte[16]),
                null);
        given(codec.parseEncryptedMessage(any())).willReturn(context);
        given(rsaExecutor.execute(any())).willReturn(new HsmRsaEncryptionResult(ByteSequence.of(new byte[] {1})));
        given(aesExecutor.execute(any()))
                .willReturn(new HsmAesEncryptionResult(ByteSequence.of("plain".getBytes()), null));

        var plaintext = service.decrypt(command);

        assertThat(plaintext).isEqualTo(ByteSequence.of("plain".getBytes()));
        then(rsaExecutor).should().execute(any());
        then(keyAgreementExecutor).shouldHaveNoInteractions();
        then(keyEncapsulationExecutor).shouldHaveNoInteractions();
    }

    @Test
    void decrypt_givenX25519Context_thenDerivesSharedSecretViaKeyAgreement() {
        var recipient = keyReference("bob-x25519", PgpPublicKeyAlgorithm.X25519);
        var command = new DecryptOpenPgpMessageCommand(message(), recipient);
        var context = new OpenPgpEncryptionFramingContext(
                PgpPublicKeyAlgorithm.X25519,
                HsmAesCipherMode.GCM,
                null,
                new HsmKeyHandle("alice-x25519"),
                null,
                ByteSequence.of(new byte[] {6, 6}),
                ByteSequence.of(new byte[12]),
                ByteSequence.of(new byte[16]));
        given(codec.parseEncryptedMessage(any())).willReturn(context);
        given(keyAgreementExecutor.execute(any()))
                .willReturn(new HsmKeyAgreementResult(ByteSequence.of(new byte[] {4, 4})));
        given(aesExecutor.execute(any()))
                .willReturn(new HsmAesEncryptionResult(ByteSequence.of("plain".getBytes()), null));

        var plaintext = service.decrypt(command);

        assertThat(plaintext).isEqualTo(ByteSequence.of("plain".getBytes()));
        then(rsaExecutor).shouldHaveNoInteractions();
        then(keyEncapsulationExecutor).shouldHaveNoInteractions();
    }

    @Test
    void decrypt_givenCompositeContext_thenCombinesAgreementAndDecapsulationResults() {
        var recipient = keyReference("bob-mlkem", PgpPublicKeyAlgorithm.ML_KEM_768_X25519);
        var command = new DecryptOpenPgpMessageCommand(message(), recipient);
        var context = new OpenPgpEncryptionFramingContext(
                PgpPublicKeyAlgorithm.ML_KEM_768_X25519,
                HsmAesCipherMode.GCM,
                null,
                new HsmKeyHandle("alice-x25519"),
                ByteSequence.of(new byte[] {3, 3, 3}),
                ByteSequence.of(new byte[] {6, 6}),
                ByteSequence.of(new byte[12]),
                ByteSequence.of(new byte[16]));
        given(codec.parseEncryptedMessage(any())).willReturn(context);
        given(keyAgreementExecutor.execute(any()))
                .willReturn(new HsmKeyAgreementResult(ByteSequence.of(new byte[] {4, 4})));
        given(keyEncapsulationExecutor.execute(any()))
                .willReturn(new HsmKeyEncapsulationResult(ByteSequence.of(new byte[] {8, 8}), null));
        given(aesExecutor.execute(any()))
                .willReturn(new HsmAesEncryptionResult(ByteSequence.of("plain".getBytes()), null));

        var plaintext = service.decrypt(command);

        assertThat(plaintext).isEqualTo(ByteSequence.of("plain".getBytes()));
        then(keyAgreementExecutor).should().execute(any());
        then(keyEncapsulationExecutor).should().execute(any());
        then(rsaExecutor).shouldHaveNoInteractions();
    }
}
