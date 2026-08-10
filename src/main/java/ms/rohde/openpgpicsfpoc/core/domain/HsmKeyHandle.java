package ms.rohde.openpgpicsfpoc.core.domain;

import java.util.Objects;
import ms.rohde.hexagonalarch.annotations.DomainValueObject;

/**
 * Opaker Verweis auf ein im HSM (bzw. im Simulations-Adapter) vorgehaltenes
 * Schluesselobjekt. Referenziert wird ueber einen Alias/Token, niemals ueber
 * das eigentliche Schluesselmaterial.
 *
 * <p>Alle Hsm-Primitiven adressieren asymmetrische Schluessel (RSA, ECC, PQC)
 * ausschliesslich ueber diesen Typ - sowohl fuer eigene als auch fuer vorab
 * im HSM registrierte fremde (Gegenstellen-)Schluessel.</p>
 */
@DomainValueObject
public record HsmKeyHandle(String alias) {

    public HsmKeyHandle {
        Objects.requireNonNull(alias, "alias darf nicht null sein");
        if (alias.isBlank()) {
            throw new IllegalArgumentException("alias darf nicht leer sein");
        }
    }
}
