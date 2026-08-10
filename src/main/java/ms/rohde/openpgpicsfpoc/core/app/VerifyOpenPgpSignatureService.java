package ms.rohde.openpgpicsfpoc.core.app;

import jakarta.inject.Inject;
import java.util.Objects;
import ms.rohde.hexagonalarch.annotations.ApplicationService;
import ms.rohde.openpgpicsfpoc.ports.inbound.VerifyOpenPgpSignatureUseCase;
import ms.rohde.openpgpicsfpoc.ports.outbound.OpenPgpMessageCodec;
import ms.rohde.openpgpicsfpoc.ports.outbound.OpenPgpVerificationRequest;

/**
 * Orchestriert die Signaturverifikation. Verifikation ist eine reine
 * Public-Key-Operation ohne Geheimnis und wird daher vollstaendig lokal ueber
 * {@link OpenPgpMessageCodec} ausgefuehrt - im Gegensatz zu den anderen drei
 * Anwendungsfaellen wird hier bewusst keine Hsm-Primitive angesprochen
 * (siehe Projektplan, Abschnitt "Kernidee der technischen Loesung").
 */
@ApplicationService
public final class VerifyOpenPgpSignatureService implements VerifyOpenPgpSignatureUseCase {

    private final OpenPgpMessageCodec codec;

    @Inject
    public VerifyOpenPgpSignatureService(OpenPgpMessageCodec codec) {
        this.codec = Objects.requireNonNull(codec, "codec darf nicht null sein");
    }

    @Override
    public boolean verify(VerifyOpenPgpSignatureCommand command) {
        Objects.requireNonNull(command, "command darf nicht null sein");
        return codec.verifySignedMessage(
                new OpenPgpVerificationRequest(command.signedMessage(), command.signerPublicKey()));
    }
}
