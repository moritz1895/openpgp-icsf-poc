package ms.rohde.openpgpicsfpoc.core.app;

import jakarta.inject.Inject;
import java.util.Objects;
import ms.rohde.hexagonalarch.annotations.ApplicationService;
import ms.rohde.openpgpicsfpoc.core.domain.OpenPgpMessage;
import ms.rohde.openpgpicsfpoc.core.domain.PgpPublicKeyAlgorithm;
import ms.rohde.openpgpicsfpoc.core.domain.UnsupportedSigningAlgorithmException;
import ms.rohde.openpgpicsfpoc.ports.inbound.SignOpenPgpMessageUseCase;
import ms.rohde.openpgpicsfpoc.ports.outbound.OpenPgpMessageCodec;
import ms.rohde.openpgpicsfpoc.ports.outbound.OpenPgpSigningRequest;

/**
 * Orchestriert das Signieren einer Nachricht: prueft, ob der Algorithmus des
 * Unterzeichner-Schluessels Signaturen unterstuetzt, und delegiert die
 * vollstaendige Erzeugung der signierten OpenPGP-Nachricht (lokale
 * Digest-Berechnung sowie der ueber die HSM delegierte Signaturschritt) an
 * {@link OpenPgpMessageCodec}.
 */
@ApplicationService
public final class SignOpenPgpMessageService implements SignOpenPgpMessageUseCase {

    private final OpenPgpMessageCodec codec;

    @Inject
    public SignOpenPgpMessageService(OpenPgpMessageCodec codec) {
        this.codec = Objects.requireNonNull(codec, "codec darf nicht null sein");
    }

    @Override
    public OpenPgpMessage sign(SignOpenPgpMessageCommand command) {
        Objects.requireNonNull(command, "command darf nicht null sein");
        PgpPublicKeyAlgorithm algorithm = command.signer().publicKey().algorithm();
        if (!algorithm.supportsSigning()) {
            throw new UnsupportedSigningAlgorithmException(algorithm);
        }

        return codec.sign(new OpenPgpSigningRequest(command.message(), command.signer()));
    }
}
