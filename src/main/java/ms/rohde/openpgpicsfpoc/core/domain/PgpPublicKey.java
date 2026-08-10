package ms.rohde.openpgpicsfpoc.core.domain;

import java.util.Objects;
import ms.rohde.hexagonalarch.annotations.DomainValueObject;

/**
 * Oeffentliches OpenPGP-Schluesselmaterial: der Algorithmus sowie die
 * algorithmusspezifisch kodierten oeffentlichen Parameter (z. B. RSA-Modulus
 * und -Exponent, ein EC-Punkt, ...).
 *
 * <p>Es existiert bewusst kein Gegenstueck mit privatem Schluesselmaterial -
 * der private Teil wird ausschliesslich ueber einen {@link HsmKeyHandle}
 * referenziert und verlaesst nie die HSM-Domaene.</p>
 */
@DomainValueObject
public record PgpPublicKey(PgpPublicKeyAlgorithm algorithm, ByteSequence encodedKeyMaterial) {

    public PgpPublicKey {
        Objects.requireNonNull(algorithm, "algorithm darf nicht null sein");
        Objects.requireNonNull(encodedKeyMaterial, "encodedKeyMaterial darf nicht null sein");
        if (encodedKeyMaterial.isEmpty()) {
            throw new IllegalArgumentException("encodedKeyMaterial darf nicht leer sein");
        }
    }
}
