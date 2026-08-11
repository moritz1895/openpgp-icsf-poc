package ms.rohde.openpgpicsfpoc.adapters.outbound.openpgp.bc;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import ms.rohde.openpgpicsfpoc.core.domain.HsmKeyHandle;

/**
 * Leitet einen deterministischen, inhaltsadressierten {@link HsmKeyHandle}
 * aus roh kodiertem oeffentlichen Schluesselmaterial ab.
 *
 * <p><b>Hintergrund:</b> {@code HsmKeyAgreementRequest} (siehe
 * {@code ports.outbound.hsm.HsmKeyAgreementRequest}) adressiert die
 * Gegenstelle einer ECDH-Schluesselaustausch-Operation ausschliesslich ueber
 * einen {@link HsmKeyHandle} - unter der dokumentierten PoC-Annahme, dass
 * Gegenstellen-Schluessel vorab im HSM als importierte Public-Key-Token
 * registriert wurden. Beim Verschluesseln ist das unproblematisch: die
 * Gegenstelle ist der Empfaenger, dessen Handle bereits explizit als Teil von
 * {@code PgpKeyReference} vorliegt.</p>
 *
 * <p>Beim Entschluesseln ist die Gegenstelle hingegen der Sender-Schluessel,
 * dessen oeffentlicher Punkt erst beim Parsen des empfangenen OpenPGP-Pakets
 * bekannt wird - das Kommando ({@code OpenPgpDecryptionRequest}) traegt dafuer
 * bewusst keinen eigenen Schluessel-Handle (der Sender-Schluessel ist laut
 * {@code EncryptOpenPgpMessageCommand} ein vorab im HSM vorhandener,
 * statischer Schluessel statt eines je Nachricht neu erzeugten ephemeren
 * Schluessels - eine bereits in der Anwendungsschicht dokumentierte
 * PoC-Vereinfachung gegenueber echtem RFC-9580-Forward-Secrecy). Diese Klasse
 * ueberbrueckt die Luecke, indem sie denselben Handle deterministisch aus dem
 * oeffentlichen Punkt selbst ableitet (SHA-256-Hash der rohen Punktbytes) -
 * ein Test-/Demo-Aufbau muss den Sender-Schluessel daher unter genau diesem
 * abgeleiteten Handle zusaetzlich zu seinem eigentlichen Alias im HSM-Schluesselspeicher
 * registrieren (siehe Integrationstests dieser Bridge sowie der CLI-Demo-Adapter unter
 * {@code adapters.inbound.cli}). Ein echter ICSF-Adapter muesste an dieser Stelle einen
 * aequivalenten Public-Key-Import-Schritt vor der eigentlichen
 * Schluesselaustausch-Operation durchfuehren - diese Einschraenkung ist unter
 * docs/technical zu dokumentieren.</p>
 *
 * <p>Bewusst {@code public}: sowohl die Testinfrastruktur dieser Bridge (gleiches Paket)
 * als auch der paketfremde CLI-Demo-Adapter muessen Sender-Schluessel exakt nach dieser
 * Konvention registrieren, damit der Entschluesselungspfad den passenden Handle wiederfindet
 * - eine paketinterne Duplikation dieser (sicherheitsrelevanten) Ableitungsregel wuerde ein
 * Drift-Risiko schaffen.</p>
 */
public final class EphemeralPeerKeyHandles {

    private static final String DIGEST_ALGORITHM = "SHA-256";
    private static final String HANDLE_PREFIX = "ecdh-peer-";

    private EphemeralPeerKeyHandles() {}

    public static HsmKeyHandle deriveFrom(byte[] rawPublicKeyMaterial) {
        try {
            MessageDigest digest = MessageDigest.getInstance(DIGEST_ALGORITHM);
            byte[] hash = digest.digest(rawPublicKeyMaterial);
            return new HsmKeyHandle(HANDLE_PREFIX + HexFormat.of().formatHex(hash));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(DIGEST_ALGORITHM + " ist auf dieser JVM nicht verfuegbar", e);
        }
    }
}
