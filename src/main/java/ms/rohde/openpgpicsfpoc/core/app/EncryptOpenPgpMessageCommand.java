package ms.rohde.openpgpicsfpoc.core.app;

import java.util.Objects;
import ms.rohde.openpgpicsfpoc.core.domain.ByteSequence;
import ms.rohde.openpgpicsfpoc.core.domain.PgpKeyReference;
import org.jspecify.annotations.Nullable;

/**
 * Kommando zum Verschluesseln einer Nachricht.
 *
 * <p>{@code senderKeyAgreementKey} wird nur fuer schluesselaustausch-basierte
 * Empfaenger-Algorithmen (X25519, klassisches ECDH-Fallback-Profil,
 * ML-KEM-768+X25519 - siehe {@code PgpPublicKeyAlgorithm.requiresSenderKeyAgreementKey()})
 * benoetigt: mangels
 * Hsm-Keygen-Port in dieser PoC wird dafuer ein vorab im HSM vorhandener,
 * statischer Sender-Schluessel verwendet statt eines je Nachricht neu
 * erzeugten ephemeren Schluessels, wie es RFC 9580 fuer maximale
 * Forward-Secrecy vorsieht. Fuer RSA-Empfaenger bleibt das Feld leer.</p>
 */
public record EncryptOpenPgpMessageCommand(
        ByteSequence plaintext, PgpKeyReference recipient, @Nullable PgpKeyReference senderKeyAgreementKey) {

    public EncryptOpenPgpMessageCommand {
        Objects.requireNonNull(plaintext, "plaintext darf nicht null sein");
        Objects.requireNonNull(recipient, "recipient darf nicht null sein");
    }
}
