package ms.rohde.openpgpicsfpoc.adapters.outbound.openpgp.bc;

import java.util.Arrays;
import ms.rohde.openpgpicsfpoc.core.domain.HsmKeyHandle;

/**
 * Bausteine fuer das komposite ML-KEM-768+X25519-Schluesselmaterial (RFC 9980,
 * Algorithmus-ID 35): Zerlegen/Zusammensetzen der beiden Teilschluessel sowie
 * die Ableitungsregel fuer den zweiten Hsm-Key-Handle.
 *
 * <p><b>Zwei-Handle-Konvention fuer Komposit-Empfaenger:</b> ein
 * {@link ms.rohde.openpgpicsfpoc.core.domain.PgpKeyReference} traegt genau
 * <em>einen</em> {@link HsmKeyHandle} - das im HSM (bzw. im
 * {@code InMemoryHsmKeyStore}-Testdouble) hinterlegte Schluesselobjekt ist
 * jedoch je ein eigenstaendiges JCA-{@code KeyPair} pro Teilalgorithmus (ein
 * ML-KEM-768-Schluesselpaar fuer {@code HsmKeyEncapsulationExecutor}, ein
 * X25519-Schluesselpaar fuer {@code HsmKeyAgreementExecutor}) und passt damit
 * nicht unter einen einzigen Handle. Diese Bridge behandelt daher den
 * primaeren Handle einer Komposit-{@code PgpKeyReference} als den Handle des
 * <b>ML-KEM-Teilschluessels</b> und leitet den Handle des
 * <b>X25519-Teilschluessels</b> deterministisch per Namenskonvention davon ab
 * ({@link #ecdhSubKeyHandle(HsmKeyHandle)}) - exakt dasselbe Prinzip wie
 * {@link EphemeralPeerKeyHandles} fuer das native X25519-Profil. Wer einen
 * Komposit-Empfaenger im (simulierten) HSM registriert (CLI-Demo,
 * Testinfrastruktur), muss beide Teilschluessel unter den jeweils passenden
 * Handles registrieren - siehe {@code DemoKeyMaterial}/{@code PgpTestKeys}.
 *
 * <p>Bewusst {@code public}: sowohl diese Bridge (Verschluesselung/Entschluesselung)
 * als auch paketfremde Registrierungscode (CLI-Demo) muessen exakt dieselbe
 * Ableitungsregel verwenden - eine paketinterne Duplikation wuerde ein
 * Drift-Risiko schaffen (siehe {@link EphemeralPeerKeyHandles}, dieselbe
 * Begruendung).</p>
 */
public final class CompositeMlKemKeyMaterial {

    /** Laenge des ECDH-Teilschluessels (X25519) in Byte, RFC 9980 Table 3. */
    public static final int ECDH_PUBLIC_KEY_LENGTH = 32;

    /** Laenge des ML-KEM-768-Teilschluessels in Byte, RFC 9980 Table 4. */
    public static final int MLKEM_PUBLIC_KEY_LENGTH = 1184;

    /** Laenge eines ML-KEM-768-Chiffrats in Byte, RFC 9980 Table 4. */
    public static final int MLKEM_CIPHERTEXT_LENGTH = 1088;

    private static final String ECDH_SUB_KEY_HANDLE_SUFFIX = "-x25519";

    private CompositeMlKemKeyMaterial() {}

    /**
     * Setzt die beiden Teilschluessel zum kompositen, roh (ohne MPI-Kodierung)
     * kodierten Schluesselmaterial nach RFC 9980 Section 4.3.2.1 zusammen:
     * {@code ecdhPublicKey(32) || mlkemPublicKey(1184)}.
     */
    public static byte[] compose(byte[] ecdhPublicKey, byte[] mlkemPublicKey) {
        if (ecdhPublicKey.length != ECDH_PUBLIC_KEY_LENGTH) {
            throw new IllegalArgumentException("ecdhPublicKey muss " + ECDH_PUBLIC_KEY_LENGTH + " Byte lang sein");
        }
        if (mlkemPublicKey.length != MLKEM_PUBLIC_KEY_LENGTH) {
            throw new IllegalArgumentException("mlkemPublicKey muss " + MLKEM_PUBLIC_KEY_LENGTH + " Byte lang sein");
        }
        return org.bouncycastle.util.Arrays.concatenate(ecdhPublicKey, mlkemPublicKey);
    }

    /** Liefert den ECDH-Teilschluessel (erste 32 Byte) aus dem kompositen Schluesselmaterial. */
    public static byte[] ecdhPublicKeyPart(byte[] compositeMaterial) {
        requireCompositeLength(compositeMaterial);
        return Arrays.copyOfRange(compositeMaterial, 0, ECDH_PUBLIC_KEY_LENGTH);
    }

    /** Liefert den ML-KEM-768-Teilschluessel (verbleibende 1184 Byte) aus dem kompositen Schluesselmaterial. */
    public static byte[] mlkemPublicKeyPart(byte[] compositeMaterial) {
        requireCompositeLength(compositeMaterial);
        return Arrays.copyOfRange(
                compositeMaterial, ECDH_PUBLIC_KEY_LENGTH, ECDH_PUBLIC_KEY_LENGTH + MLKEM_PUBLIC_KEY_LENGTH);
    }

    /**
     * Leitet den Handle des X25519-Teilschluessels deterministisch aus dem
     * primaeren (ML-KEM-)Handle einer Komposit-{@code PgpKeyReference} ab -
     * siehe Klassen-JavaDoc.
     */
    public static HsmKeyHandle ecdhSubKeyHandle(HsmKeyHandle primaryHandle) {
        return new HsmKeyHandle(primaryHandle.alias() + ECDH_SUB_KEY_HANDLE_SUFFIX);
    }

    private static void requireCompositeLength(byte[] compositeMaterial) {
        int expected = ECDH_PUBLIC_KEY_LENGTH + MLKEM_PUBLIC_KEY_LENGTH;
        if (compositeMaterial.length != expected) {
            throw new IllegalArgumentException(
                    "Komposit-Schluesselmaterial muss genau " + expected + " Byte lang sein, war "
                            + compositeMaterial.length);
        }
    }
}
