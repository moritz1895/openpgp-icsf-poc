package ms.rohde.openpgpicsfpoc.core.domain;

import java.util.Objects;
import ms.rohde.hexagonalarch.annotations.DomainValueObject;
import org.jspecify.annotations.Nullable;

/**
 * Oeffentliches OpenPGP-Schluesselmaterial: der Algorithmus, die
 * algorithmusspezifisch kodierten oeffentlichen Parameter (z. B. RSA-Modulus
 * und -Exponent, ein EC-Punkt, ...) sowie - ausschliesslich fuer das
 * klassische ECDH-Fallback-Profil ({@link PgpPublicKeyAlgorithm#ECDH}) - die
 * tatsaechlich verwendete Kurve.
 *
 * <p>Es existiert bewusst kein Gegenstueck mit privatem Schluesselmaterial -
 * der private Teil wird ausschliesslich ueber einen {@link HsmKeyHandle}
 * referenziert und verlaesst nie die HSM-Domaene.</p>
 *
 * <p>{@code curve} ist nur fuer {@link PgpPublicKeyAlgorithm#ECDH} gesetzt:
 * RFC 6637 parametrisiert das klassische ECDH-Profil ueber eine Kurven-OID im
 * Schluessel selbst (NIST P-256/P-384 etc.), waehrend RFC 9580
 * {@link PgpPublicKeyAlgorithm#X25519} als eigene, kurvenfeste
 * Algorithmus-ID ohne separaten Kurven-Parameter definiert - fuer alle
 * anderen Algorithmen (einschliesslich {@code X25519}) muss {@code curve}
 * {@code null} bleiben.</p>
 */
@DomainValueObject
public record PgpPublicKey(
        PgpPublicKeyAlgorithm algorithm, ByteSequence encodedKeyMaterial, @Nullable PgpEllipticCurve curve) {

    public PgpPublicKey {
        Objects.requireNonNull(algorithm, "algorithm darf nicht null sein");
        Objects.requireNonNull(encodedKeyMaterial, "encodedKeyMaterial darf nicht null sein");
        if (encodedKeyMaterial.isEmpty()) {
            throw new IllegalArgumentException("encodedKeyMaterial darf nicht leer sein");
        }
        if (algorithm == PgpPublicKeyAlgorithm.ECDH && curve == null) {
            throw new IllegalArgumentException("curve muss fuer PgpPublicKeyAlgorithm.ECDH gesetzt sein");
        }
        if (algorithm != PgpPublicKeyAlgorithm.ECDH && curve != null) {
            throw new IllegalArgumentException("curve darf nur fuer PgpPublicKeyAlgorithm.ECDH gesetzt sein");
        }
    }

    /**
     * Bequemlichkeits-Konstruktor fuer alle Algorithmen ausser
     * {@link PgpPublicKeyAlgorithm#ECDH}, die keine gesonderte Kurvenangabe
     * benoetigen.
     */
    public PgpPublicKey(PgpPublicKeyAlgorithm algorithm, ByteSequence encodedKeyMaterial) {
        this(algorithm, encodedKeyMaterial, null);
    }
}
