package ms.rohde.openpgpicsfpoc.core.app;

import jakarta.inject.Inject;
import java.util.Objects;
import ms.rohde.hexagonalarch.annotations.ApplicationService;
import ms.rohde.openpgpicsfpoc.core.domain.ByteSequence;
import ms.rohde.openpgpicsfpoc.ports.inbound.DecryptOpenPgpMessageUseCase;
import ms.rohde.openpgpicsfpoc.ports.outbound.OpenPgpDecryptionRequest;
import ms.rohde.openpgpicsfpoc.ports.outbound.OpenPgpMessageCodec;

/**
 * Orchestriert die Entschluesselung einer OpenPGP-Nachricht: delegiert das
 * Parsen des Paketformats, das Aufloesen des Sitzungsschluessels (bzw. des
 * gemeinsamen Shared Secrets) ueber die Hsm-Primitiven sowie die
 * Nutzlastentschluesselung vollstaendig an {@link OpenPgpMessageCodec}.
 * Welcher Algorithmus vorliegt, ergibt sich erst aus dem Paketformat selbst -
 * die Anwendungsschicht hat dafuer keine eigene fachliche Vorpruefung zu
 * leisten (siehe Projektplan, Abschnitt "Kernidee der technischen Loesung").
 */
@ApplicationService
public final class DecryptOpenPgpMessageService implements DecryptOpenPgpMessageUseCase {

    private final OpenPgpMessageCodec codec;

    @Inject
    public DecryptOpenPgpMessageService(OpenPgpMessageCodec codec) {
        this.codec = Objects.requireNonNull(codec, "codec darf nicht null sein");
    }

    @Override
    public ByteSequence decrypt(DecryptOpenPgpMessageCommand command) {
        Objects.requireNonNull(command, "command darf nicht null sein");
        return codec.decrypt(new OpenPgpDecryptionRequest(command.message(), command.recipient()));
    }
}
