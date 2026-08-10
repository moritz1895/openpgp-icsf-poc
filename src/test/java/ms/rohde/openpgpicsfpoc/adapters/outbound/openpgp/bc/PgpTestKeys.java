package ms.rohde.openpgpicsfpoc.adapters.outbound.openpgp.bc;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.EdECPublicKey;
import java.security.interfaces.XECPublicKey;
import java.security.spec.ECGenParameterSpec;
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
