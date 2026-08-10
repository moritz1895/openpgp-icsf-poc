package ms.rohde.openpgpicsfpoc.ports.outbound;

import ms.rohde.hexagonalarch.annotations.InfrastructureServicePort;
import ms.rohde.openpgpicsfpoc.core.domain.OpenPgpMessage;

/**
 * Outbound-Port fuer die eigentliche OpenPGP-Paketkodierung/-dekodierung
 * (RFC 4880 / RFC 9580 / RFC 9980 Framing: Paket-Header, MPI-Kodierung,
 * Radix64/Armor, ...).
 *
 * <p><b>Diese Iteration definiert ausschliesslich das Interface.</b> Die
 * konkrete Implementierung folgt in einer Folge-Iteration als Bouncy-
 * Castle-Bridge-Adapter (siehe Projektplan, Abschnitt "Kernidee der
 * technischen Loesung"), der Bouncy Castles Extension-Points
 * ({@code PGPContentSignerBuilder}, {@code PublicKeyKeyEncryptionMethodGenerator},
 * {@code PGPDataEncryptorBuilder}, ...) gegen die Hsm-Executor-Ports
 * implementiert. Eine Dummy-Implementierung dieses Ports ergibt fachlich
 * keinen Sinn, solange kein echtes OpenPGP-Framing vorliegt.</p>
 *
 * <p>Die Anwendungsservices fuehren die kryptographischen Hsm-Operationen
 * (Sitzungsschluessel verpacken/ableiten, Nutzlast ver-/entschluesseln,
 * signieren) bereits selbst aus und uebergeben diesem Port lediglich die
 * fertigen kryptographischen Artefakte samt Metadaten zur Kodierung - bzw.
 * erhalten beim Entschluesseln/Verifizieren die aus dem Paketformat
 * extrahierten Parameter zurueck. Dieser Schnitt kann sich aendern, sobald
 * der Bridge-Adapter reale OpenPGP-Chunking-/AEAD-Rahmenbedingungen
 * beruecksichtigen muss.</p>
 */
@InfrastructureServicePort
public interface OpenPgpMessageCodec {

    /**
     * Kodiert die bereits berechneten Verschluesselungsartefakte in eine
     * gueltige OpenPGP-Nachricht.
     */
    OpenPgpMessage frameEncryptedMessage(OpenPgpEncryptionFramingRequest request);

    /**
     * Extrahiert die zur Entschluesselung benoetigten kryptographischen
     * Parameter aus einer verschluesselten OpenPGP-Nachricht.
     */
    OpenPgpEncryptionFramingContext parseEncryptedMessage(OpenPgpMessage message);

    /**
     * Kodiert eine bereits berechnete Signatur zusammen mit der Nachricht in
     * eine gueltige signierte OpenPGP-Nachricht.
     */
    OpenPgpMessage frameSignedMessage(OpenPgpSigningFramingRequest request);

    /**
     * Prueft eine Signatur lokal gegen das oeffentliche Schluesselmaterial
     * des Unterzeichners - reine Public-Key-Operation, keine HSM-Operation
     * involviert.
     */
    boolean verifySignedMessage(OpenPgpVerificationRequest request);
}
