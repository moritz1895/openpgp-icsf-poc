package ms.rohde.openpgpicsfpoc.core.app;

import jakarta.inject.Inject;
import java.util.Objects;
import ms.rohde.hexagonalarch.annotations.ApplicationService;
import ms.rohde.openpgpicsfpoc.core.domain.ByteSequence;
import ms.rohde.openpgpicsfpoc.core.domain.MessageDigestCalculator;
import ms.rohde.openpgpicsfpoc.core.domain.OpenPgpMessage;
import ms.rohde.openpgpicsfpoc.core.domain.PgpPublicKeyAlgorithm;
import ms.rohde.openpgpicsfpoc.core.domain.UnsupportedSigningAlgorithmException;
import ms.rohde.openpgpicsfpoc.ports.inbound.SignOpenPgpMessageUseCase;
import ms.rohde.openpgpicsfpoc.ports.outbound.OpenPgpMessageCodec;
import ms.rohde.openpgpicsfpoc.ports.outbound.OpenPgpSigningFramingRequest;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmSignature;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmSignatureAlgorithm;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmSignatureExecutor;

/**
 * Orchestriert das Signieren einer Nachricht: berechnet den Digest lokal
 * (kein Geheimnis involviert), signiert ihn ueber {@link HsmSignatureExecutor}
 * und delegiert das Paket-Framing an {@link OpenPgpMessageCodec}.
 */
@ApplicationService
public final class SignOpenPgpMessageService implements SignOpenPgpMessageUseCase {

    private final HsmSignatureExecutor signatureExecutor;
    private final OpenPgpMessageCodec codec;
    private final MessageDigestCalculator digestCalculator;

    @Inject
    public SignOpenPgpMessageService(
            HsmSignatureExecutor signatureExecutor, OpenPgpMessageCodec codec, MessageDigestCalculator digestCalculator) {
        this.signatureExecutor = Objects.requireNonNull(signatureExecutor, "signatureExecutor darf nicht null sein");
        this.codec = Objects.requireNonNull(codec, "codec darf nicht null sein");
        this.digestCalculator = Objects.requireNonNull(digestCalculator, "digestCalculator darf nicht null sein");
    }

    @Override
    public OpenPgpMessage sign(SignOpenPgpMessageCommand command) {
        Objects.requireNonNull(command, "command darf nicht null sein");
        PgpPublicKeyAlgorithm algorithm = command.signer().publicKey().algorithm();
        if (!algorithm.supportsSigning()) {
            throw new UnsupportedSigningAlgorithmException(algorithm);
        }

        ByteSequence digest = digestCalculator.sha256(command.message());
        var signatureResult = signatureExecutor.execute(HsmSignature.builder()
                .keyHandle(command.signer().keyHandle())
                .algorithm(toHsmSignatureAlgorithm(algorithm))
                .digest(digest)
                .build());

        return codec.frameSignedMessage(new OpenPgpSigningFramingRequest(
                command.message(), algorithm, command.signer(), digest, signatureResult.signature()));
    }

    private static HsmSignatureAlgorithm toHsmSignatureAlgorithm(PgpPublicKeyAlgorithm algorithm) {
        return switch (algorithm) {
            case RSA -> HsmSignatureAlgorithm.RSA_PKCS1V15;
            case ECDSA -> HsmSignatureAlgorithm.ECDSA;
            case EDDSA -> HsmSignatureAlgorithm.EDDSA;
            case ML_DSA_65_ED25519 -> HsmSignatureAlgorithm.ML_DSA_65_ED25519;
            case X25519, ML_KEM_768_X25519 -> throw new UnsupportedSigningAlgorithmException(algorithm);
        };
    }
}
