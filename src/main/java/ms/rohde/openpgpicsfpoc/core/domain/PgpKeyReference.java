package ms.rohde.openpgpicsfpoc.core.domain;

import java.util.Objects;
import ms.rohde.hexagonalarch.annotations.DomainEntity;

/**
 * Eine im System nutzbare OpenPGP-Schluesselidentitaet: die Kombination aus
 * dem oeffentlichen Schluesselmaterial ({@link PgpPublicKey}, benoetigt fuer
 * Paket-Framing und lokale Signaturverifikation) und dem {@link HsmKeyHandle},
 * ueber den die zugehoerige HSM-seitige Operation angestossen wird.
 *
 * <p>Wird sowohl fuer eigene Schluessel als auch fuer vorab im HSM
 * registrierte Gegenstellen-Schluessel (z. B. der Empfaenger einer
 * verschluesselten Nachricht) verwendet - die Identitaet dieser Entitaet ist
 * der {@link HsmKeyHandle}.</p>
 */
@DomainEntity
public final class PgpKeyReference {

    private final HsmKeyHandle keyHandle;
    private final PgpPublicKey publicKey;

    public PgpKeyReference(HsmKeyHandle keyHandle, PgpPublicKey publicKey) {
        this.keyHandle = Objects.requireNonNull(keyHandle, "keyHandle darf nicht null sein");
        this.publicKey = Objects.requireNonNull(publicKey, "publicKey darf nicht null sein");
    }

    public HsmKeyHandle keyHandle() {
        return keyHandle;
    }

    public PgpPublicKey publicKey() {
        return publicKey;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof PgpKeyReference other)) {
            return false;
        }
        return keyHandle.equals(other.keyHandle);
    }

    @Override
    public int hashCode() {
        return keyHandle.hashCode();
    }

    @Override
    public String toString() {
        return "PgpKeyReference[keyHandle=" + keyHandle + ", algorithm=" + publicKey.algorithm() + "]";
    }
}
