package ms.rohde.openpgpicsfpoc.core.app;

import jakarta.inject.Inject;
import java.util.Objects;
import ms.rohde.hexagonalarch.annotations.ApplicationService;
import ms.rohde.openpgpicsfpoc.core.domain.ByteSequence;
import ms.rohde.openpgpicsfpoc.core.domain.HybridSharedSecretCombiner;
import ms.rohde.openpgpicsfpoc.core.domain.MissingKeyAgreementKeyException;
import ms.rohde.openpgpicsfpoc.core.domain.OpenPgpMessage;
import ms.rohde.openpgpicsfpoc.core.domain.PgpEncryptionProfile;
import ms.rohde.openpgpicsfpoc.core.domain.PgpKeyReference;
import ms.rohde.openpgpicsfpoc.core.domain.PgpPublicKeyAlgorithm;
import ms.rohde.openpgpicsfpoc.core.domain.SymmetricSessionKeyGenerator;
import ms.rohde.openpgpicsfpoc.core.domain.UnsupportedEncryptionAlgorithmException;
import ms.rohde.openpgpicsfpoc.ports.inbound.EncryptOpenPgpMessageUseCase;
import ms.rohde.openpgpicsfpoc.ports.outbound.OpenPgpEncryptionFramingRequest;
import ms.rohde.openpgpicsfpoc.ports.outbound.OpenPgpMessageCodec;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmAesCipherMode;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmAesEncryption;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmAesEncryptionExecutor;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmCipherOperation;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmEllipticCurve;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmKeyAgreement;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmKeyAgreementExecutor;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmKeyEncapsulation;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmKeyEncapsulationExecutor;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmKeyEncapsulationOperation;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmKeyEncapsulationResult;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmRsaEncryption;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmRsaEncryptionExecutor;

/**
 * Orchestriert die Verschluesselung einer Nachricht: erzeugt lokal einen
 * ephemeren Sitzungsschluessel bzw. leitet ueber Schluesselaustausch/
 * -kapselung ein Shared Secret ab (je nach Empfaenger-Algorithmus), fuehrt
 * die Nutzlastverschluesselung ueber die Hsm-Primitiven aus und delegiert
 * das eigentliche OpenPGP-Paket-Framing an {@link OpenPgpMessageCodec}.
 */
@ApplicationService
public final class EncryptOpenPgpMessageService implements EncryptOpenPgpMessageUseCase {

    private static final int SESSION_KEY_LENGTH_BYTES = 32;
    private static final int GCM_NONCE_LENGTH_BYTES = 12;
    private static final int CFB_BLOCK_LENGTH_BYTES = 16;

    private final HsmRsaEncryptionExecutor rsaExecutor;
    private final HsmAesEncryptionExecutor aesExecutor;
    private final HsmKeyAgreementExecutor keyAgreementExecutor;
    private final HsmKeyEncapsulationExecutor keyEncapsulationExecutor;
    private final OpenPgpMessageCodec codec;
    private final SymmetricSessionKeyGenerator sessionKeyGenerator;
    private final HybridSharedSecretCombiner hybridSharedSecretCombiner;

    @Inject
    public EncryptOpenPgpMessageService(
            HsmRsaEncryptionExecutor rsaExecutor,
            HsmAesEncryptionExecutor aesExecutor,
            HsmKeyAgreementExecutor keyAgreementExecutor,
            HsmKeyEncapsulationExecutor keyEncapsulationExecutor,
            OpenPgpMessageCodec codec,
            SymmetricSessionKeyGenerator sessionKeyGenerator,
            HybridSharedSecretCombiner hybridSharedSecretCombiner) {
        this.rsaExecutor = Objects.requireNonNull(rsaExecutor, "rsaExecutor darf nicht null sein");
        this.aesExecutor = Objects.requireNonNull(aesExecutor, "aesExecutor darf nicht null sein");
        this.keyAgreementExecutor =
                Objects.requireNonNull(keyAgreementExecutor, "keyAgreementExecutor darf nicht null sein");
        this.keyEncapsulationExecutor =
                Objects.requireNonNull(keyEncapsulationExecutor, "keyEncapsulationExecutor darf nicht null sein");
        this.codec = Objects.requireNonNull(codec, "codec darf nicht null sein");
        this.sessionKeyGenerator =
                Objects.requireNonNull(sessionKeyGenerator, "sessionKeyGenerator darf nicht null sein");
        this.hybridSharedSecretCombiner =
                Objects.requireNonNull(hybridSharedSecretCombiner, "hybridSharedSecretCombiner darf nicht null sein");
    }

    @Override
    public OpenPgpMessage encrypt(EncryptOpenPgpMessageCommand command) {
        Objects.requireNonNull(command, "command darf nicht null sein");
        PgpPublicKeyAlgorithm algorithm = command.recipient().publicKey().algorithm();
        if (!algorithm.supportsEncryption()) {
            throw new UnsupportedEncryptionAlgorithmException(algorithm);
        }

        ByteSequence sessionKey;
        ByteSequence wrappedSessionKey = null;
        ByteSequence encapsulatedKey = null;

        switch (algorithm) {
            case RSA -> {
                sessionKey = sessionKeyGenerator.generate(SESSION_KEY_LENGTH_BYTES);
                wrappedSessionKey = rsaExecutor
                        .execute(HsmRsaEncryption.builder()
                                .keyHandle(command.recipient().keyHandle())
                                .operation(HsmCipherOperation.ENCRYPT)
                                .input(sessionKey)
                                .build())
                        .output();
            }
            case X25519 -> sessionKey = agreeSharedSecret(command);
            case ML_KEM_768_X25519 -> {
                ByteSequence classicalSharedSecret = agreeSharedSecret(command);
                HsmKeyEncapsulationResult kemResult = keyEncapsulationExecutor.execute(HsmKeyEncapsulation.builder()
                        .keyHandle(command.recipient().keyHandle())
                        .operation(HsmKeyEncapsulationOperation.ENCAPSULATE)
                        .build());
                encapsulatedKey = kemResult.encapsulatedKey();
                sessionKey = hybridSharedSecretCombiner.combine(classicalSharedSecret, kemResult.sharedSecret());
            }
            default -> throw new UnsupportedEncryptionAlgorithmException(algorithm);
        }

        HsmAesCipherMode cipherMode = cipherModeFor(command.profile());
        ByteSequence initializationVector = sessionKeyGenerator.generate(
                cipherMode == HsmAesCipherMode.GCM ? GCM_NONCE_LENGTH_BYTES : CFB_BLOCK_LENGTH_BYTES);

        var aesResult = aesExecutor.execute(HsmAesEncryption.builder()
                .sessionKey(sessionKey)
                .cipherMode(cipherMode)
                .operation(HsmCipherOperation.ENCRYPT)
                .input(command.plaintext())
                .initializationVector(initializationVector)
                .build());

        return codec.frameEncryptedMessage(new OpenPgpEncryptionFramingRequest(
                command.profile(),
                algorithm,
                command.recipient(),
                command.senderKeyAgreementKey(),
                wrappedSessionKey,
                encapsulatedKey,
                aesResult.output(),
                initializationVector,
                aesResult.authenticationTag()));
    }

    private ByteSequence agreeSharedSecret(EncryptOpenPgpMessageCommand command) {
        PgpKeyReference senderKey = command.senderKeyAgreementKey();
        if (senderKey == null) {
            throw new MissingKeyAgreementKeyException(command.recipient().publicKey().algorithm());
        }
        return keyAgreementExecutor
                .execute(HsmKeyAgreement.builder()
                        .curve(HsmEllipticCurve.X25519)
                        .localKeyHandle(senderKey.keyHandle())
                        .peerKeyHandle(command.recipient().keyHandle())
                        .build())
                .sharedSecret();
    }

    private static HsmAesCipherMode cipherModeFor(PgpEncryptionProfile profile) {
        return switch (profile) {
            case AEAD_V2 -> HsmAesCipherMode.GCM;
            case LEGACY_CFB_MDC -> HsmAesCipherMode.CFB;
        };
    }
}
