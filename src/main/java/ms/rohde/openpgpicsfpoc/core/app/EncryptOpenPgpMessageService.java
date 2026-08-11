package ms.rohde.openpgpicsfpoc.core.app;

import jakarta.inject.Inject;
import java.util.Objects;
import ms.rohde.hexagonalarch.annotations.ApplicationService;
import ms.rohde.openpgpicsfpoc.core.domain.MissingKeyAgreementKeyException;
import ms.rohde.openpgpicsfpoc.core.domain.OpenPgpMessage;
import ms.rohde.openpgpicsfpoc.core.domain.PgpPublicKeyAlgorithm;
import ms.rohde.openpgpicsfpoc.core.domain.UnsupportedEncryptionAlgorithmException;
import ms.rohde.openpgpicsfpoc.ports.inbound.EncryptOpenPgpMessageUseCase;
import ms.rohde.openpgpicsfpoc.ports.outbound.OpenPgpEncryptionRequest;
import ms.rohde.openpgpicsfpoc.ports.outbound.OpenPgpMessageCodec;

/**
 * Orchestriert die Verschluesselung einer Nachricht: prueft die fachlichen
 * Voraussetzungen (unterstuetzter Algorithmus, vorhandener Sender-Schluessel
 * fuer schluesselaustausch-basierte Empfaenger-Algorithmen) und delegiert die
 * vollstaendige kryptographische Nachrichtenerzeugung an
 * {@link OpenPgpMessageCodec}. Fuehrt selbst keine Hsm-Operation aus - diese
 * werden erst von der Implementierung des Codec-Ports (Bouncy-Castle-Bridge-
 * Adapter) angestossen (siehe Projektplan, Abschnitt "Kernidee der
 * technischen Loesung").
 */
@ApplicationService
public final class EncryptOpenPgpMessageService implements EncryptOpenPgpMessageUseCase {

    private final OpenPgpMessageCodec codec;

    @Inject
    public EncryptOpenPgpMessageService(OpenPgpMessageCodec codec) {
        this.codec = Objects.requireNonNull(codec, "codec darf nicht null sein");
    }

    @Override
    public OpenPgpMessage encrypt(EncryptOpenPgpMessageCommand command) {
        Objects.requireNonNull(command, "command darf nicht null sein");
        PgpPublicKeyAlgorithm algorithm = command.recipient().publicKey().algorithm();
        if (!algorithm.supportsEncryption()) {
            throw new UnsupportedEncryptionAlgorithmException(algorithm);
        }
        if (algorithm.requiresSenderKeyAgreementKey() && command.senderKeyAgreementKey() == null) {
            throw new MissingKeyAgreementKeyException(algorithm);
        }

        return codec.encrypt(new OpenPgpEncryptionRequest(
                command.plaintext(), command.recipient(), command.senderKeyAgreementKey()));
    }
}
