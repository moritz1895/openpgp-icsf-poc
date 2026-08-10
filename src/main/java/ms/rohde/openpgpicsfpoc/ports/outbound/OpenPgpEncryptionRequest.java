package ms.rohde.openpgpicsfpoc.ports.outbound;

import java.util.Objects;
import ms.rohde.openpgpicsfpoc.core.domain.ByteSequence;
import ms.rohde.openpgpicsfpoc.core.domain.PgpEncryptionProfile;
import ms.rohde.openpgpicsfpoc.core.domain.PgpKeyReference;
import org.jspecify.annotations.Nullable;

/**
 * Anfrage an {@link OpenPgpMessageCodec#encrypt(OpenPgpEncryptionRequest)}:
 * Klartext, Empfaenger und das gewuenschte Verschluesselungsprofil. Die
 * vollstaendige kryptographische Erzeugung der OpenPGP-Nachricht (frischer
 * Sitzungsschluessel, dessen Verpackung/Ableitung fuer den Empfaenger, sowie
 * die Nutzlastverschluesselung) obliegt der Implementierung dieses Ports -
 * die Anwendungsschicht uebergibt hier bewusst nur fachliche Eingabedaten,
 * keine bereits berechneten kryptographischen Artefakte (siehe Projektplan,
 * Abschnitt "Kernidee der technischen Loesung").
 *
 * <p>{@code senderKeyAgreementKey} wird nur fuer schluesselaustausch-basierte
 * Empfaenger-Algorithmen benoetigt (natives X25519, klassisches
 * ECDH-Fallback-Profil, die klassische Komponente des kompositen
 * ML-KEM-768+X25519-Verfahrens - siehe
 * {@code PgpPublicKeyAlgorithm.requiresSenderKeyAgreementKey()}). Fuer
 * RSA-Empfaenger bleibt das Feld leer.</p>
 */
public record OpenPgpEncryptionRequest(
        ByteSequence plaintext,
        PgpEncryptionProfile profile,
        PgpKeyReference recipient,
        @Nullable PgpKeyReference senderKeyAgreementKey) {

    public OpenPgpEncryptionRequest {
        Objects.requireNonNull(plaintext, "plaintext darf nicht null sein");
        Objects.requireNonNull(profile, "profile darf nicht null sein");
        Objects.requireNonNull(recipient, "recipient darf nicht null sein");
    }
}
