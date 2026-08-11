package ms.rohde.openpgpicsfpoc.ports.outbound;

import ms.rohde.hexagonalarch.annotations.InfrastructureServicePort;
import ms.rohde.openpgpicsfpoc.core.domain.ByteSequence;
import ms.rohde.openpgpicsfpoc.core.domain.OpenPgpMessage;

/**
 * Outbound-Port fuer die vollstaendige kryptographische Erzeugung und das
 * Parsen einer OpenPGP-Nachricht (RFC 4880 / RFC 9580 / RFC 9980): sowohl
 * das Paket-Framing (Paket-Header, MPI-Kodierung, Radix64/Armor, ...) als
 * auch die eigentlichen kryptographischen Operationen (Sitzungsschluessel
 * erzeugen/verpacken/ableiten, Nutzlast ver-/entschluesseln, signieren).
 *
 * <p>Dieser Zuschnitt ersetzt eine fruehere Iteration, in der die
 * Anwendungsservices die Hsm-Executor-Ports selbst aufriefen und diesem Port
 * nur noch die fertig berechneten kryptographischen Artefakte zum reinen
 * Paket-Framing uebergaben. Das ist mit einer echten Bouncy-Castle-Anbindung
 * nicht vereinbar: Bouncy Castles Orchestrierungsklassen
 * ({@code PGPEncryptedDataGenerator}, {@code PGPSignatureGenerator}, ...)
 * rufen selbst zur Laufzeit unsere SPI-Implementierungen
 * ({@code PublicKeyKeyEncryptionMethodGenerator}, {@code PGPContentSignerBuilder},
 * ...) auf, die intern die Hsm-Executor-Ports ansprechen. Die
 * Anwendungsschicht kann diese Hsm-Operationen daher nicht mehr selbst
 * vorwegnehmen, sondern uebergibt Klartext/Empfaenger/Schluesselreferenzen
 * unveraendert an diesen Port (siehe Projektplan, Abschnitt "Kernidee der
 * technischen Loesung"). Die konkrete Implementierung folgt in einer
 * Folge-Iteration als Bouncy-Castle-Bridge-Adapter; eine Dummy-Implementierung
 * dieses Ports ergibt fachlich keinen Sinn, solange kein echtes
 * OpenPGP-Framing vorliegt.</p>
 */
@InfrastructureServicePort
public interface OpenPgpMessageCodec {

    /**
     * Verschluesselt den Klartext aus der Anfrage vollstaendig zu einer
     * fertigen OpenPGP-Nachricht - einschliesslich Sitzungsschluessel-Erzeugung,
     * dessen Verpackung/Ableitung fuer den Empfaenger sowie der
     * Nutzlastverschluesselung nach SEIPD v2/AEAD (RFC 9580; das einzige von
     * dieser PoC unterstuetzte Verschluesselungsprofil).
     */
    OpenPgpMessage encrypt(OpenPgpEncryptionRequest request);

    /**
     * Entschluesselt eine OpenPGP-Nachricht vollstaendig zum Klartext -
     * einschliesslich Parsen des Paketformats, Aufloesen des
     * Sitzungsschluessels (bzw. des gemeinsamen Shared Secrets) ueber den
     * passenden Schluessel-Handle sowie der Nutzlastentschluesselung.
     */
    ByteSequence decrypt(OpenPgpDecryptionRequest request);

    /**
     * Erzeugt eine vollstaendige signierte OpenPGP-Nachricht - einschliesslich
     * lokaler Digest-Berechnung und des ueber die HSM delegierten
     * Signaturschritts.
     */
    OpenPgpMessage sign(OpenPgpSigningRequest request);

    /**
     * Prueft eine Signatur lokal gegen das oeffentliche Schluesselmaterial
     * des Unterzeichners - reine Public-Key-Operation, keine HSM-Operation
     * involviert.
     */
    boolean verify(OpenPgpVerificationRequest request);
}
