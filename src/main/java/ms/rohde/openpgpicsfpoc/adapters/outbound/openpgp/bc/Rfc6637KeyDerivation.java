package ms.rohde.openpgpicsfpoc.adapters.outbound.openpgp.bc;

import java.io.ByteArrayOutputStream;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;

/**
 * Lokale, unkritische Schluesselableitung fuer die ECDH-basierten
 * Verschluesselungsprofile - sowohl das klassische Profil nach RFC 6637
 * (Abschnitt 7/8) als auch das native X25519/X448-Profil nach RFC 9580
 * (Abschnitt 5.1.6/11.5.1). Nur die vorangehende ECDH-Punktmultiplikation
 * selbst laeuft ueber die HSM ({@code HsmKeyAgreementExecutor}) - die
 * anschliessende Ableitung des Schluessel-Wickel-Schluessels aus dem Shared
 * Secret ist ein oeffentlicher, deterministischer Algorithmus ohne
 * Geheimnisbezug zur HSM (siehe Projektplan, Abschnitt "Kernidee der
 * technischen Loesung").
 */
final class Rfc6637KeyDerivation {

    private static final byte[] ANONYMOUS_SENDER = {
        0x41, 0x6E, 0x6F, 0x6E, 0x79, 0x6D, 0x6F, 0x75, 0x73, 0x20, 0x53, 0x65, 0x6E, 0x64, 0x65, 0x72, 0x20, 0x20,
        0x20, 0x20
    };

    private Rfc6637KeyDerivation() {}

    /**
     * RFC 6637 Section 8 "Param": {@code curve_OID_len || curve_OID ||
     * public_key_alg_ID || 03 || 01 || KDF_hash_ID || KEK_alg_ID ||
     * "Anonymous Sender    " || recipient_fingerprint}.
     */
    static byte[] classicalUserKeyingMaterial(
            byte[] curveOidEncoded, int hashAlgorithmTag, int symmetricKeyAlgorithmTag, byte[] recipientFingerprint) {
        var out = new ByteArrayOutputStream();
        out.write(curveOidEncoded, 1, curveOidEncoded.length - 1);
        out.write(18); // PublicKeyAlgorithmTags.ECDH
        out.write(0x03);
        out.write(0x01);
        out.write(hashAlgorithmTag);
        out.write(symmetricKeyAlgorithmTag);
        out.writeBytes(ANONYMOUS_SENDER);
        out.writeBytes(recipientFingerprint);
        return out.toByteArray();
    }

    /**
     * RFC 6637 Section 7 KDF: {@code leftmost(keyLen, Hash(0x00000001 || ZB
     * || Param))}, wobei {@code ZB} die affine X-Koordinate des ECDH-Shared-Secret-Punkts ist.
     */
    static byte[] classicalKdf(int hashAlgorithmTag, int symmetricKeyAlgorithmTag, byte[] zb, byte[] param) {
        var digest = digestFor(hashAlgorithmTag);
        digest.update((byte) 0x00);
        digest.update((byte) 0x00);
        digest.update((byte) 0x00);
        digest.update((byte) 0x01);
        digest.update(zb);
        digest.update(param);
        return Arrays.copyOf(digest.digest(), keyLength(symmetricKeyAlgorithmTag));
    }

    /**
     * RFC 9580 Section 5.1.6/11.5.1 (natives X25519-Profil): HKDF-SHA256 ohne
     * Salt ueber {@code ephemeralPublicKey || recipientPublicKeyMaterial ||
     * sharedSecret} mit Info {@code "OpenPGP X25519"}.
     */
    static byte[] nativeX25519Kdf(byte[] ephemeralPublicKey, byte[] recipientKeyMaterial, byte[] sharedSecret) {
        var ikm = new ByteArrayOutputStream();
        ikm.writeBytes(ephemeralPublicKey);
        ikm.writeBytes(recipientKeyMaterial);
        ikm.writeBytes(sharedSecret);
        var info = "OpenPGP X25519".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        return hkdfSha256(ikm.toByteArray(), null, info, 16);
    }

    /**
     * RFC 9580 Section 5.13.2 (SEIPD v2/AEAD): HKDF-SHA256 mit dem
     * Sitzungsschluessel als Eingabematerial, dem 32-Byte-Salt aus dem SEIPD-Paket
     * und dem 5-Byte-Paketpraefix als Info, liefert {@code keyLen + ivLen -
     * 8} Bytes (Sitzungs-/Nachrichtenschluessel gefolgt vom Nonce-Praefix).
     */
    static byte[] aeadMessageKeyAndIvMaterial(byte[] sessionKey, byte[] salt, byte[] info, int outputLength) {
        return hkdfSha256(sessionKey, salt, info, outputLength);
    }

    private static byte[] hkdfSha256(byte[] ikm, byte[] salt, byte[] info, int length) {
        try {
            var effectiveSalt = salt != null ? salt : new byte[32];
            var extractMac = Mac.getInstance("HmacSHA256");
            extractMac.init(new SecretKeySpec(effectiveSalt, "HmacSHA256"));
            var prk = extractMac.doFinal(ikm);

            var expandMac = Mac.getInstance("HmacSHA256");
            expandMac.init(new SecretKeySpec(prk, "HmacSHA256"));
            var output = new byte[length];
            byte[] previousBlock = new byte[0];
            int written = 0;
            byte counter = 1;
            while (written < length) {
                expandMac.reset();
                expandMac.update(previousBlock);
                expandMac.update(info);
                expandMac.update(counter);
                previousBlock = expandMac.doFinal();
                int toCopy = Math.min(previousBlock.length, length - written);
                System.arraycopy(previousBlock, 0, output, written, toCopy);
                written += toCopy;
                counter++;
            }
            return output;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HKDF-SHA256 fehlgeschlagen: " + e.getMessage(), e);
        }
    }

    private static MessageDigest digestFor(int hashAlgorithmTag) {
        var name =
                switch (hashAlgorithmTag) {
                    case HashAlgorithmTags.SHA256 -> "SHA-256";
                    case HashAlgorithmTags.SHA384 -> "SHA-384";
                    case HashAlgorithmTags.SHA512 -> "SHA-512";
                    default ->
                        throw new IllegalArgumentException("Nicht unterstuetzter Hash-Algorithmus: " + hashAlgorithmTag);
                };
        try {
            return MessageDigest.getInstance(name);
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(name + " ist auf dieser JVM nicht verfuegbar", e);
        }
    }

    static int keyLength(int symmetricKeyAlgorithmTag) {
        return switch (symmetricKeyAlgorithmTag) {
            case SymmetricKeyAlgorithmTags.AES_128 -> 16;
            case SymmetricKeyAlgorithmTags.AES_192 -> 24;
            case SymmetricKeyAlgorithmTags.AES_256 -> 32;
            default ->
                throw new IllegalArgumentException(
                        "Nicht unterstuetzter symmetrischer Algorithmus: " + symmetricKeyAlgorithmTag);
        };
    }
}
