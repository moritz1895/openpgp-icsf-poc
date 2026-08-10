package ms.rohde.openpgpicsfpoc.core.domain;

import java.util.Objects;
import ms.rohde.hexagonalarch.annotations.DomainValueObject;

/**
 * Eine fertig kodierte OpenPGP-Nachricht (Binaer- oder Radix64/Armor-Form).
 *
 * <p>Die eigentliche Paketkodierung (Header, MPI-Kodierung, Armor, ...) ist
 * nicht Teil dieser Iteration und wird von einem spaeteren Bouncy-Castle-
 * Bridge-Adapter hinter {@code OpenPgpMessageCodec} erzeugt. Diese Klasse ist
 * lediglich der Werttyp, der das Ergebnis transportiert.</p>
 */
@DomainValueObject
public record OpenPgpMessage(ByteSequence encoded) {

    public OpenPgpMessage {
        Objects.requireNonNull(encoded, "encoded darf nicht null sein");
        if (encoded.isEmpty()) {
            throw new IllegalArgumentException("encoded darf nicht leer sein");
        }
    }
}
