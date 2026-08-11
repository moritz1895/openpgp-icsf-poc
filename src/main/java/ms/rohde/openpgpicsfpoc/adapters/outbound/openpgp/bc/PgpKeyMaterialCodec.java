package ms.rohde.openpgpicsfpoc.adapters.outbound.openpgp.bc;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.Date;
import ms.rohde.openpgpicsfpoc.core.domain.PgpEllipticCurve;
import ms.rohde.openpgpicsfpoc.core.domain.PgpPublicKey;
import ms.rohde.openpgpicsfpoc.core.domain.PgpPublicKeyAlgorithm;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.bcpg.BCPGKey;
import org.bouncycastle.bcpg.BCPGObject;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.ECDHPublicBCPGKey;
import org.bouncycastle.bcpg.ECDSAPublicBCPGKey;
import org.bouncycastle.bcpg.Ed25519PublicBCPGKey;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.RSAPublicBCPGKey;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bcpg.X25519PublicBCPGKey;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;

/**
 * Uebersetzt zwischen dem projekteigenen, algorithmus-neutralen
 * Schluesselmodell ({@link PgpPublicKey}) und Bouncy Castles
 * paketorientiertem OpenPGP-Schluesselmodell ({@link PGPPublicKey}).
 *
 * <p><b>Kodierungskonvention fuer {@link PgpPublicKey#encodedKeyMaterial()}</b>
 * (von dieser Bridge-Implementierung festgelegt, da der Port selbst keine
 * Kodierung vorschreibt): fuer {@link PgpPublicKeyAlgorithm#RSA} die
 * X.509-SubjectPublicKeyInfo-DER-Kodierung ({@code java.security.PublicKey#getEncoded()});
 * fuer alle ECC-Algorithmen (klassisches {@link PgpPublicKeyAlgorithm#ECDH},
 * {@link PgpPublicKeyAlgorithm#ECDSA}, natives {@link PgpPublicKeyAlgorithm#X25519},
 * natives {@link PgpPublicKeyAlgorithm#EDDSA}) die rohe, OpenPGP-native
 * Punktkodierung (unkomprimierter SEC1-Punkt {@code 0x04 || X || Y} fuer die
 * NIST-Kurven, 32 Rohbytes fuer X25519/Ed25519) - exakt die Bytes, die auch
 * in das jeweilige OpenPGP-Schluesselpaket wandern, ohne weitere Umkodierung.</p>
 *
 * <p>Diese PoC modelliert keine Schluessel-Zertifizierung/-Lebensdauer (siehe
 * Feature-Spezifikation, Abschnitt "Out of Scope"); alle erzeugten Pakete
 * verwenden daher einheitlich Schluesselformat-Version 4 mit einem festen
 * Erzeugungszeitpunkt (Unix-Epoche).</p>
 */
final class PgpKeyMaterialCodec {

    static final Date FIXED_CREATION_TIME = Date.from(Instant.EPOCH);

    static final ASN1ObjectIdentifier NIST_P256_OID = new ASN1ObjectIdentifier("1.2.840.10045.3.1.7");
    static final ASN1ObjectIdentifier NIST_P384_OID = new ASN1ObjectIdentifier("1.3.132.0.34");

    /**
     * Algorithmus-ID fuer ML-KEM-768+X25519 nach RFC 9980 Section 9.1 (Table 2).
     * {@code bcpg-jdk18on} 1.85 kennt diesen Wert nicht als benannte
     * {@link PublicKeyAlgorithmTags}-Konstante - er wird daher als rohe Zahl gefuehrt.
     */
    static final int COMPOSITE_ML_KEM_768_X25519_ALGORITHM_TAG = 35;

    private static final BcKeyFingerprintCalculator FINGERPRINT_CALCULATOR = new BcKeyFingerprintCalculator();

    private PgpKeyMaterialCodec() {}

    /**
     * Baut ein Bouncy-Castle-{@link PGPPublicKey} aus dem projekteigenen
     * {@link PgpPublicKey} - reine Paket-Framing-Uebersetzung, keine
     * kryptographische Operation.
     */
    static PGPPublicKey toPgpPublicKey(PgpPublicKey publicKey) {
        try {
            var packet = toPublicKeyPacket(publicKey);
            return new PGPPublicKey(packet, FINGERPRINT_CALCULATOR);
        } catch (PGPException e) {
            throw new IllegalArgumentException("Ungueltiges oeffentliches Schluesselmaterial: " + e.getMessage(), e);
        }
    }

    static PublicKeyPacket toPublicKeyPacket(PgpPublicKey publicKey) {
        int algorithmTag = toPacketAlgorithmTag(publicKey.algorithm());
        BCPGKey key = toBcpgKey(publicKey);
        return new PublicKeyPacket(PublicKeyPacket.VERSION_4, algorithmTag, FIXED_CREATION_TIME, key);
    }

    private static BCPGKey toBcpgKey(PgpPublicKey publicKey) {
        byte[] material = publicKey.encodedKeyMaterial().value();
        return switch (publicKey.algorithm()) {
            case RSA -> rsaKeyFromX509(material);
            case ECDH -> {
                var curve = curveOid(publicKey.curve());
                var hashAndSymAlg = classicalEcdhAlgorithmPair(publicKey.curve());
                yield new ECDHPublicBCPGKey(
                        curve, new BigInteger(1, material), hashAndSymAlg[0], hashAndSymAlg[1]);
            }
            case ECDSA -> ecdsaKey(material);
            case X25519 -> new X25519PublicBCPGKey(material);
            case EDDSA -> new Ed25519PublicBCPGKey(material);
            case ML_KEM_768_X25519 -> new CompositeMlKemPublicBCPGKey(material);
            default ->
                throw new IllegalArgumentException(
                        "Algorithmus " + publicKey.algorithm() + " wird von dieser Bridge nicht unterstuetzt (die"
                                + " Signatur-Seite ML-DSA-65+Ed25519 erfordert v6-Schluessel und ist ausserhalb des"
                                + " Scopes dieser Iteration)");
        };
    }

    private static ECDSAPublicBCPGKey ecdsaKey(byte[] material) {
        try {
            return new ECDSAPublicBCPGKey(curveOid(curveFromPointLength(material)), new BigInteger(1, material));
        } catch (IOException e) {
            throw new IllegalArgumentException("Ungueltiges ECDSA-Schluesselmaterial: " + e.getMessage(), e);
        }
    }

    private static RSAPublicBCPGKey rsaKeyFromX509(byte[] x509EncodedSubjectPublicKeyInfo) {
        try {
            var keyFactory = KeyFactory.getInstance("RSA");
            var publicKey =
                    (RSAPublicKey) keyFactory.generatePublic(new X509EncodedKeySpec(x509EncodedSubjectPublicKeyInfo));
            return new RSAPublicBCPGKey(publicKey.getModulus(), publicKey.getPublicExponent());
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("Ungueltiges RSA-Schluesselmaterial: " + e.getMessage(), e);
        }
    }

    /**
     * Leitet die klassische NIST-Kurve aus der Laenge eines unkomprimierten
     * SEC1-Punkts ({@code 0x04 || X || Y}) ab: 65 Byte fuer P-256 (32 Byte je
     * Koordinate), 97 Byte fuer P-384 (48 Byte je Koordinate).
     *
     * <p>{@link PgpPublicKeyAlgorithm#ECDSA} traegt in {@link PgpPublicKey}
     * bewusst keine explizite Kurve (nur {@code ECDH} tut das, siehe
     * JavaDoc auf {@link PgpPublicKey}) - fuer die in dieser Iteration
     * unterstuetzten Kurven P-256/P-384 ist die Punktlaenge jedoch eindeutig,
     * sodass keine zusaetzliche Domaenen-Aenderung noetig ist.</p>
     */
    static PgpEllipticCurve curveFromPointLength(byte[] uncompressedPoint) {
        return switch (uncompressedPoint.length) {
            case 65 -> PgpEllipticCurve.P256;
            case 97 -> PgpEllipticCurve.P384;
            default ->
                throw new IllegalArgumentException(
                        "Unbekannte ECDSA-Punktlaenge " + uncompressedPoint.length
                                + " - erwartet 65 (P-256) oder 97 (P-384) Byte");
        };
    }

    static int toPacketAlgorithmTag(PgpPublicKeyAlgorithm algorithm) {
        return switch (algorithm) {
            case RSA -> PublicKeyAlgorithmTags.RSA_GENERAL;
            case ECDH -> PublicKeyAlgorithmTags.ECDH;
            case ECDSA -> PublicKeyAlgorithmTags.ECDSA;
            case X25519 -> PublicKeyAlgorithmTags.X25519;
            case EDDSA -> PublicKeyAlgorithmTags.Ed25519;
            case ML_KEM_768_X25519 -> COMPOSITE_ML_KEM_768_X25519_ALGORITHM_TAG;
            default ->
                throw new IllegalArgumentException(
                        "Algorithmus " + algorithm + " wird von dieser Bridge nicht unterstuetzt");
        };
    }

    static ASN1ObjectIdentifier curveOid(PgpEllipticCurve curve) {
        return switch (curve) {
            case P256 -> NIST_P256_OID;
            case P384 -> NIST_P384_OID;
            case X25519 ->
                throw new IllegalArgumentException(
                        "X25519 wird nativ (PgpPublicKeyAlgorithm.X25519) statt ueber das klassische "
                                + "ECDH-Kurvenprofil abgebildet");
        };
    }

    /**
     * Hash- und symmetrischer Schluesselalgorithmus, die RFC 6637 fest an
     * eine Kurve koppelt (Tabelle in RFC 6637 Section 11 / RFC 9580 Section
     * 9.2): P-256 mit SHA-256/AES-128, P-384 mit SHA-384/AES-192.
     *
     * @return zweielementiges Array {@code {hashAlgorithmTag, symmetricKeyAlgorithmTag}}
     */
    static ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmEllipticCurve toHsmCurve(PgpEllipticCurve curve) {
        return switch (curve) {
            case P256 -> ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmEllipticCurve.P256;
            case P384 -> ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmEllipticCurve.P384;
            case X25519 -> ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmEllipticCurve.X25519;
        };
    }

    static int[] classicalEcdhAlgorithmPair(PgpEllipticCurve curve) {
        return switch (curve) {
            case P256 -> new int[] {HashAlgorithmTags.SHA256, SymmetricKeyAlgorithmTags.AES_128};
            case P384 -> new int[] {HashAlgorithmTags.SHA384, SymmetricKeyAlgorithmTags.AES_192};
            case X25519 ->
                throw new IllegalArgumentException(
                        "X25519 wird nativ (PgpPublicKeyAlgorithm.X25519) statt ueber das klassische "
                                + "ECDH-Kurvenprofil abgebildet");
        };
    }

    /**
     * Baut einen opaken {@link PGPPrivateKey}-Platzhalter fuer den
     * Signaturschritt: Bouncy Castles {@code PGPSignatureGenerator.init(...)}
     * verlangt aus API-Gruenden ein {@link PGPPrivateKey}-Objekt, dessen
     * eigentliches Schluesselmaterial ({@link PGPPrivateKey#getPrivateKeyDataPacket()})
     * von dieser Bridge jedoch niemals gelesen wird - der tatsaechliche
     * private Schluessel bleibt ausschliesslich als {@code HsmKeyHandle}
     * bekannt und verlaesst nie die HSM-Domaene (siehe Projektplan,
     * Smartcard/OpenPGP-Card-Modell). Der hier erzeugte {@link BCPGKey} traegt
     * keine echten Schluesseldaten.
     */
    static PGPPrivateKey placeholderPrivateKey(PublicKeyPacket publicKeyPacket, long keyId) {
        return new PGPPrivateKey(keyId, publicKeyPacket, NoMaterialBcpgKey.INSTANCE);
    }

    /**
     * Komposit-Schluesselmaterial fuer ML-KEM-768+X25519 (RFC 9980 Section 4.3.2.1):
     * {@code ecdhPublicKey(32) || mlkemPublicKey(1184)}, insgesamt 1216 Byte, als
     * <b>fixed-length</b> Rohbytes ohne MPI-Kodierung in das Paket eingebettet.
     *
     * <p>{@code bcpg-jdk18on} 1.85 bietet dafuer keine typisierte Schluesselklasse; das
     * generische {@code OctetArrayBCPGKey} waere zwar strukturell passend, seine
     * Konstruktoren sind jedoch paketsichtbar (Paket {@code org.bouncycastle.bcpg}) und
     * von hier aus nicht aufrufbar - diese Klasse erweitert {@link BCPGObject} und
     * implementiert {@link BCPGKey} daher selbst. <b>Wichtig:</b> {@link BCPGObject} ist hier
     * Pflicht, ein reines {@code implements BCPGKey} (wie beim aehnlichen, aber nie
     * tatsaechlich serialisierten {@link NoMaterialBcpgKey}) fuehrt zu einer
     * {@code ClassCastException} - {@link PublicKeyPacket#getEncodedContents()} (von der
     * Fingerabdruckberechnung {@link BcKeyFingerprintCalculator} und jedem echten
     * Paket-Schreibvorgang durchlaufen) castet das Schluesselfeld intern unbedingt nach
     * {@code BCPGObject} und ruft dessen {@link #encode(BCPGOutputStream)} auf.
     * {@link BCPGObject#getEncoded()} liefert bereits eine korrekte
     * Default-Implementierung darauf aufbauend.</p>
     *
     * <p>Siehe {@link CompositeMlKemKeyMaterial} fuer das Zerlegen dieser Rohbytes in die
     * beiden Teilschluessel.</p>
     */
    static final class CompositeMlKemPublicBCPGKey extends BCPGObject implements BCPGKey {

        private final byte[] material;

        CompositeMlKemPublicBCPGKey(byte[] material) {
            if (material.length
                    != CompositeMlKemKeyMaterial.ECDH_PUBLIC_KEY_LENGTH + CompositeMlKemKeyMaterial.MLKEM_PUBLIC_KEY_LENGTH) {
                throw new IllegalArgumentException(
                        "Komposit-Schluesselmaterial muss genau "
                                + (CompositeMlKemKeyMaterial.ECDH_PUBLIC_KEY_LENGTH
                                        + CompositeMlKemKeyMaterial.MLKEM_PUBLIC_KEY_LENGTH)
                                + " Byte lang sein, war " + material.length);
            }
            this.material = material.clone();
        }

        @Override
        public String getFormat() {
            return "MLKEM768X25519";
        }

        @Override
        public void encode(BCPGOutputStream out) throws IOException {
            out.write(material);
        }

        /**
         * Ueberschreibt bewusst {@link BCPGObject#getEncoded()} (das eine checked
         * {@code IOException} auswirft) - {@link BCPGKey#getEncoded()} (via
         * {@code Encodable}) deklariert keine checked Exception, exakt wie es reale
         * BC-Schluesselklassen (z. B. {@code X25519PublicBCPGKey} ueber
         * {@code OctetArrayBCPGKey}) an dieser Stelle ebenfalls tun.
         */
        @Override
        public byte[] getEncoded() {
            return material.clone();
        }
    }

    private enum NoMaterialBcpgKey implements BCPGKey {
        INSTANCE;

        @Override
        public String getFormat() {
            return "OPAQUE-HSM-HANDLE";
        }

        @Override
        public byte[] getEncoded() {
            return new byte[0];
        }
    }
}
