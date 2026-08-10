package ms.rohde.openpgpicsfpoc.core.domain;

import java.security.SecureRandom;
import java.util.Objects;
import jakarta.inject.Inject;
import ms.rohde.hexagonalarch.annotations.DomainService;

/**
 * Erzeugt kryptographisch zufaelliges Sitzungsschluessel-Material lokal
 * (mangels Hsm-Keygen-Port in dieser PoC, siehe Projektplan).
 *
 * <p>Der so erzeugte symmetrische Sitzungsschluessel ist ephemer und wird im
 * Verlauf der Verschluesselung ohnehin fuer den/die Empfaenger verpackt
 * ({@code HsmRsaEncryption}) bzw. per Schluesselaustausch geschuetzt
 * ({@code HsmKeyAgreement}/{@code HsmKeyEncapsulation}) - anders als
 * langlebiges privates Schluesselmaterial verlaesst er bewusst kurzzeitig
 * die Anwendungsschicht.</p>
 */
@DomainService
public final class SymmetricSessionKeyGenerator {

    private final SecureRandom secureRandom;

    @Inject
    public SymmetricSessionKeyGenerator() {
        this(new SecureRandom());
    }

    public SymmetricSessionKeyGenerator(SecureRandom secureRandom) {
        this.secureRandom = Objects.requireNonNull(secureRandom, "secureRandom darf nicht null sein");
    }

    public ByteSequence generate(int lengthInBytes) {
        if (lengthInBytes <= 0) {
            throw new IllegalArgumentException("lengthInBytes muss positiv sein");
        }
        byte[] bytes = new byte[lengthInBytes];
        secureRandom.nextBytes(bytes);
        return ByteSequence.of(bytes);
    }
}
