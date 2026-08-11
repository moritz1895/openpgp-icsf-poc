package ms.rohde.openpgpicsfpoc.adapters.outbound.openpgp.bc;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * {@code multiKeyCombine}-Schluesselkombinierer nach RFC 9980 Section 4.2.1: leitet aus
 * den beiden Shared Secrets der kompositen ML-KEM+ECDH-Verschluesselung sowie
 * Bindungsinformationen den Schluessel-Wickel-Schluessel (KEK) ab, mit dem der
 * eigentliche Sitzungsschluessel per RFC-3394-AES-Key-Wrap verpackt wird
 * ({@link HsmAesKeyWrap}).
 *
 * <p>Rein lokale, deterministische SHA3-256-Berechnung ohne HSM-Bezug (die Eingaben
 * sind bereits die - nicht mehr geheimen - Ausgaben der beiden KEM-Operationen bzw.
 * oeffentliche Paketfelder), daher mit Standard-JDK-{@code MessageDigest} statt einer
 * Bouncy-Castle-Implementierung berechnet:</p>
 *
 * <pre>
 * KEK = SHA3-256(
 *           mlkemKeyShare || ecdhKeyShare ||
 *           ecdhCipherText || ecdhPublicKey ||
 *           algId || domSep || len(domSep)
 *       )
 * </pre>
 *
 * <p>{@code domSep} ist die UTF-8-Kodierung des konstanten Strings
 * {@code "OpenPGPCompositeKDFv1"} (21 Oktette), {@code len(domSep)} das einzelne Oktett
 * mit diesem Laengenwert.</p>
 *
 * <p>Gegen die Appendix-A.2-Testvektoren aus RFC 9980 verifiziert (siehe
 * {@code HsmCompositeMlKemKeyCombinerTest}) - siehe dort auch fuer die Herkunft der
 * dabei verwendeten {@code ecdhCipherText}-/{@code ecdhPublicKey}-Werte.</p>
 */
final class HsmCompositeMlKemKeyCombiner {

    private static final String DIGEST_ALGORITHM = "SHA3-256";
    private static final byte[] DOMAIN_SEPARATOR = "OpenPGPCompositeKDFv1".getBytes(StandardCharsets.UTF_8);

    private HsmCompositeMlKemKeyCombiner() {}

    static byte[] multiKeyCombine(
            byte[] mlkemKeyShare, byte[] ecdhKeyShare, byte[] ecdhCipherText, byte[] ecdhPublicKey, byte algId) {
        var input = new ByteArrayOutputStream();
        input.writeBytes(mlkemKeyShare);
        input.writeBytes(ecdhKeyShare);
        input.writeBytes(ecdhCipherText);
        input.writeBytes(ecdhPublicKey);
        input.write(algId);
        input.writeBytes(DOMAIN_SEPARATOR);
        input.write(DOMAIN_SEPARATOR.length);

        try {
            return MessageDigest.getInstance(DIGEST_ALGORITHM).digest(input.toByteArray());
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(DIGEST_ALGORITHM + " ist auf dieser JVM nicht verfuegbar", e);
        }
    }
}
