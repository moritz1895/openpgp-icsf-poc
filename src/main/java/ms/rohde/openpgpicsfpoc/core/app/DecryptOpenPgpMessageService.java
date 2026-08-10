package ms.rohde.openpgpicsfpoc.core.app;

import jakarta.inject.Inject;
import java.util.Objects;
import ms.rohde.hexagonalarch.annotations.ApplicationService;
import ms.rohde.openpgpicsfpoc.core.domain.ByteSequence;
import ms.rohde.openpgpicsfpoc.core.domain.HybridSharedSecretCombiner;
import ms.rohde.openpgpicsfpoc.core.domain.PgpPublicKeyAlgorithm;
import ms.rohde.openpgpicsfpoc.core.domain.UnsupportedEncryptionAlgorithmException;
import ms.rohde.openpgpicsfpoc.ports.inbound.DecryptOpenPgpMessageUseCase;
import ms.rohde.openpgpicsfpoc.ports.outbound.OpenPgpEncryptionFramingContext;
import ms.rohde.openpgpicsfpoc.ports.outbound.OpenPgpMessageCodec;
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
 * Orchestriert die Entschluesselung einer OpenPGP-Nachricht: laesst
 * {@link OpenPgpMessageCodec} die kryptographischen Parameter aus dem
 * Paketformat extrahieren, loest darauf aufbauend ueber die Hsm-Primitiven
 * den Sitzungsschluessel auf (bzw. das gemeinsame Shared Secret) und
 * entschluesselt anschliessend die Nutzlast.
 */
@ApplicationService
public final class DecryptOpenPgpMessageService implements DecryptOpenPgpMessageUseCase {

    private final HsmRsaEncryptionExecutor rsaExecutor;
    private final HsmAesEncryptionExecutor aesExecutor;
    private final HsmKeyAgreementExecutor keyAgreementExecutor;
    private final HsmKeyEncapsulationExecutor keyEncapsulationExecutor;
    private final OpenPgpMessageCodec codec;
    private final HybridSharedSecretCombiner hybridSharedSecretCombiner;

    @Inject
    public DecryptOpenPgpMessageService(
            HsmRsaEncryptionExecutor rsaExecutor,
            HsmAesEncryptionExecutor aesExecutor,
            HsmKeyAgreementExecutor keyAgreementExecutor,
            HsmKeyEncapsulationExecutor keyEncapsulationExecutor,
            OpenPgpMessageCodec codec,
            HybridSharedSecretCombiner hybridSharedSecretCombiner) {
        this.rsaExecutor = Objects.requireNonNull(rsaExecutor, "rsaExecutor darf nicht null sein");
        this.aesExecutor = Objects.requireNonNull(aesExecutor, "aesExecutor darf nicht null sein");
        this.keyAgreementExecutor =
                Objects.requireNonNull(keyAgreementExecutor, "keyAgreementExecutor darf nicht null sein");
        this.keyEncapsulationExecutor =
                Objects.requireNonNull(keyEncapsulationExecutor, "keyEncapsulationExecutor darf nicht null sein");
        this.codec = Objects.requireNonNull(codec, "codec darf nicht null sein");
        this.hybridSharedSecretCombiner =
                Objects.requireNonNull(hybridSharedSecretCombiner, "hybridSharedSecretCombiner darf nicht null sein");
    }

    @Override
    public ByteSequence decrypt(DecryptOpenPgpMessageCommand command) {
        Objects.requireNonNull(command, "command darf nicht null sein");
        OpenPgpEncryptionFramingContext context = codec.parseEncryptedMessage(command.message());
        PgpPublicKeyAlgorithm algorithm = context.algorithm();

        ByteSequence sessionKey =
                switch (algorithm) {
                    case RSA -> resolveRsaSessionKey(command, context);
                    case X25519 -> resolveKeyAgreementSharedSecret(command, context);
                    case ML_KEM_768_X25519 -> resolveHybridSharedSecret(command, context);
                    default -> throw new UnsupportedEncryptionAlgorithmException(algorithm);
                };

        var aesResult = aesExecutor.execute(HsmAesEncryption.builder()
                .sessionKey(sessionKey)
                .cipherMode(context.cipherMode())
                .operation(HsmCipherOperation.DECRYPT)
                .input(context.ciphertext())
                .initializationVector(context.initializationVector())
                .authenticationTag(context.authenticationTag())
                .build());
        return aesResult.output();
    }

    private ByteSequence resolveRsaSessionKey(DecryptOpenPgpMessageCommand command, OpenPgpEncryptionFramingContext context) {
        return rsaExecutor
                .execute(HsmRsaEncryption.builder()
                        .keyHandle(command.recipient().keyHandle())
                        .operation(HsmCipherOperation.DECRYPT)
                        .input(Objects.requireNonNull(
                                context.wrappedSessionKey(), "wrappedSessionKey fehlt im RSA-Kontext"))
                        .build())
                .output();
    }

    private ByteSequence resolveKeyAgreementSharedSecret(
            DecryptOpenPgpMessageCommand command, OpenPgpEncryptionFramingContext context) {
        return keyAgreementExecutor
                .execute(HsmKeyAgreement.builder()
                        .curve(HsmEllipticCurve.X25519)
                        .localKeyHandle(command.recipient().keyHandle())
                        .peerKeyHandle(Objects.requireNonNull(
                                context.senderKeyAgreementKeyHandle(), "senderKeyAgreementKeyHandle fehlt im Kontext"))
                        .build())
                .sharedSecret();
    }

    private ByteSequence resolveHybridSharedSecret(
            DecryptOpenPgpMessageCommand command, OpenPgpEncryptionFramingContext context) {
        ByteSequence classicalSharedSecret = resolveKeyAgreementSharedSecret(command, context);
        HsmKeyEncapsulationResult kemResult = keyEncapsulationExecutor.execute(HsmKeyEncapsulation.builder()
                .keyHandle(command.recipient().keyHandle())
                .operation(HsmKeyEncapsulationOperation.DECAPSULATE)
                .encapsulatedKey(Objects.requireNonNull(context.encapsulatedKey(), "encapsulatedKey fehlt im Kontext"))
                .build());
        return hybridSharedSecretCombiner.combine(classicalSharedSecret, kemResult.sharedSecret());
    }
}
