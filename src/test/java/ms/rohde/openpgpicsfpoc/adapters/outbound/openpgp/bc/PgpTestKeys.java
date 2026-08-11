package ms.rohde.openpgpicsfpoc.adapters.outbound.openpgp.bc;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.EdECPublicKey;
import java.security.interfaces.XECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import ms.rohde.openpgpicsfpoc.core.domain.ByteSequence;
import ms.rohde.openpgpicsfpoc.core.domain.PgpEllipticCurve;
import ms.rohde.openpgpicsfpoc.core.domain.PgpPublicKey;
import ms.rohde.openpgpicsfpoc.core.domain.PgpPublicKeyAlgorithm;

/**
 * Testhilfe: erzeugt echte JCA-Schluesselpaare und uebersetzt deren
 * oeffentlichen Teil in die von {@link PgpKeyMaterialCodec} dokumentierte
 * Rohbyte-Kodierungskonvention dieser Bridge (siehe dortiges JavaDoc). Reine
 * Testinfrastruktur - kein Produktivcode.
 */
final class PgpTestKeys {

    private PgpTestKeys() {}

    static KeyPair generateRsa() throws GeneralSecurityException {
        var generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    static KeyPair generateEc(PgpEllipticCurve curve) throws GeneralSecurityException {
        var generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec(curve == PgpEllipticCurve.P256 ? "secp256r1" : "secp384r1"));
        return generator.generateKeyPair();
    }

    static KeyPair generateX25519() throws GeneralSecurityException {
        return KeyPairGenerator.getInstance("X25519").generateKeyPair();
    }

    static KeyPair generateEd25519() throws GeneralSecurityException {
        return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    }

    /** Erzeugt ein ML-KEM-768-Schluesselpaar ueber das seit Java 24 (JEP 496) native JCA-Provider. */
    static KeyPair generateMlKem768() throws GeneralSecurityException {
        return KeyPairGenerator.getInstance("ML-KEM-768").generateKeyPair();
    }

    /**
     * Extrahiert die rohe FIPS-203-Kodierung eines ML-KEM-oeffentlichen Schluessels aus
     * dessen JCA-X.509-{@code SubjectPublicKeyInfo}-DER-Kodierung ({@code getEncoded()})
     * durch generisches Ueberspringen der aeusseren SEQUENCE, der
     * Algorithmus-Kennung-SEQUENCE und des Unused-Bits-Oktetts der BIT STRING - kein
     * ML-KEM-spezifischer Sonderfall, sondern die allgemeine X.509-SPKI-Struktur (siehe
     * RFC 5280 Section 4.1). Keine zusaetzliche ASN.1-Bibliotheksabhaengigkeit noetig
     * (weder {@code bcpg-jdk18on} noch {@code bcutil-jdk18on} bringen die dafuer noetigen
     * {@code org.bouncycastle.asn1.x509}-Klassen mit).
     */
    static byte[] rawMlKemPublicKey(KeyPair keyPair) {
        return derBitStringContent(keyPair.getPublic().getEncoded());
    }

    private static byte[] derBitStringContent(byte[] x509Encoded) {
        int[] cursor = {0};
        readDerTlvHeader(x509Encoded, cursor); // aeussere SEQUENCE (SubjectPublicKeyInfo)
        int algorithmIdentifierStart = cursor[0];
        int[] algorithmCursor = {algorithmIdentifierStart};
        int[] algorithmHeader = readDerTlvHeader(x509Encoded, algorithmCursor);
        int bitStringStart = algorithmCursor[0] + algorithmHeader[1]; // Inhalt der AlgorithmIdentifier-SEQUENCE ueberspringen
        int[] bitStringCursor = {bitStringStart};
        int[] bitStringHeader = readDerTlvHeader(x509Encoded, bitStringCursor);
        int contentStart = bitStringCursor[0];
        int contentLength = bitStringHeader[1];
        // erstes Inhaltsoktett der BIT STRING = Anzahl ungenutzter Bits (0 fuer byte-alignierte Schluessel)
        return Arrays.copyOfRange(x509Encoded, contentStart + 1, contentStart + contentLength);
    }

    /**
     * Liest einen DER-TLV-Header (Tag + Laenge, Kurz- oder Langform) ab {@code cursor[0]},
     * setzt {@code cursor[0]} auf den Beginn des Inhalts und liefert {@code {tag, length}}.
     */
    private static int[] readDerTlvHeader(byte[] data, int[] cursor) {
        int offset = cursor[0];
        int tag = data[offset] & 0xFF;
        int lengthByte = data[offset + 1] & 0xFF;
        int length;
        int headerLength;
        if ((lengthByte & 0x80) == 0) {
            length = lengthByte;
            headerLength = 2;
        } else {
            int lengthOctets = lengthByte & 0x7F;
            length = 0;
            for (int i = 0; i < lengthOctets; i++) {
                length = (length << 8) | (data[offset + 2 + i] & 0xFF);
            }
            headerLength = 2 + lengthOctets;
        }
        cursor[0] = offset + headerLength;
        return new int[] {tag, length};
    }

    static PgpPublicKey rsaPublicKey(KeyPair keyPair) {
        return new PgpPublicKey(PgpPublicKeyAlgorithm.RSA, ByteSequence.of(keyPair.getPublic().getEncoded()));
    }

    static PgpPublicKey ecdhPublicKey(KeyPair keyPair, PgpEllipticCurve curve) {
        return new PgpPublicKey(
                PgpPublicKeyAlgorithm.ECDH, ByteSequence.of(rawEcPoint((ECPublicKey) keyPair.getPublic(), curve)), curve);
    }

    static PgpPublicKey ecdsaPublicKey(KeyPair keyPair, PgpEllipticCurve curve) {
        return new PgpPublicKey(
                PgpPublicKeyAlgorithm.ECDSA, ByteSequence.of(rawEcPoint((ECPublicKey) keyPair.getPublic(), curve)));
    }

    static PgpPublicKey x25519PublicKey(KeyPair keyPair) {
        return new PgpPublicKey(PgpPublicKeyAlgorithm.X25519, ByteSequence.of(rawXdhPoint(keyPair)));
    }

    static PgpPublicKey eddsaPublicKey(KeyPair keyPair) {
        return new PgpPublicKey(PgpPublicKeyAlgorithm.EDDSA, ByteSequence.of(rawEd25519Point(keyPair)));
    }

    private static byte[] rawEcPoint(ECPublicKey key, PgpEllipticCurve curve) {
        int fieldSize = curve == PgpEllipticCurve.P256 ? 32 : 48;
        byte[] x = unsignedFixedLength(key.getW().getAffineX(), fieldSize);
        byte[] y = unsignedFixedLength(key.getW().getAffineY(), fieldSize);
        byte[] result = new byte[1 + 2 * fieldSize];
        result[0] = 0x04;
        System.arraycopy(x, 0, result, 1, fieldSize);
        System.arraycopy(y, 0, result, 1 + fieldSize, fieldSize);
        return result;
    }

    private static byte[] rawXdhPoint(KeyPair keyPair) {
        var xecPublicKey = (XECPublicKey) keyPair.getPublic();
        byte[] bigEndian = unsignedFixedLength(xecPublicKey.getU(), 32);
        return reverse(bigEndian);
    }

    private static byte[] rawEd25519Point(KeyPair keyPair) {
        var edPublicKey = (EdECPublicKey) keyPair.getPublic();
        byte[] bigEndianY = unsignedFixedLength(edPublicKey.getPoint().getY(), 32);
        byte[] littleEndianY = reverse(bigEndianY);
        if (edPublicKey.getPoint().isXOdd()) {
            littleEndianY[31] |= (byte) 0x80;
        }
        return littleEndianY;
    }

    private static byte[] unsignedFixedLength(BigInteger value, int length) {
        byte[] signed = value.toByteArray();
        byte[] result = new byte[length];
        int copyLength = Math.min(length, signed.length);
        System.arraycopy(signed, signed.length - copyLength, result, length - copyLength, copyLength);
        return result;
    }

    private static byte[] reverse(byte[] value) {
        byte[] result = new byte[value.length];
        for (int i = 0; i < value.length; i++) {
            result[i] = value[value.length - 1 - i];
        }
        return result;
    }
}
