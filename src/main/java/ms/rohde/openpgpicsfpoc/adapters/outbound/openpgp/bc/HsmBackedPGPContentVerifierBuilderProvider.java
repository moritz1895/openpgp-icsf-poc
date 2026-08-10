package ms.rohde.openpgpicsfpoc.adapters.outbound.openpgp.bc;

import java.io.OutputStream;
import java.security.DigestOutputStream;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.spec.EdECPoint;
import java.security.spec.EdECPublicKeySpec;
import java.security.spec.NamedParameterSpec;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.operator.PGPContentVerifier;
import org.bouncycastle.openpgp.operator.PGPContentVerifierBuilder;
import org.bouncycastle.openpgp.operator.PGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;

/**
 * Prueft Signaturen ausschliesslich lokal, ohne HSM-Bezug (siehe
 * Feature-Spezifikation "openpgp-signing", Domain Rule 4).
 *
 * <p>Fuer RSA-PKCS#1v1.5 und ECDSA wird die unveraenderte
 * {@link JcaPGPContentVerifierBuilderProvider} von Bouncy Castle verwendet
 * (kein eigener Provider registriert, es werden ausschliesslich die
 * Standard-JDK-Provider genutzt) - das "hash-then-sign"-Schema dieser beiden
 * Algorithmen ist zwischen HSM-Signaturerzeugung und lokaler Verifikation
 * konsistent.</p>
 *
 * <p>Fuer natives EdDSA (Ed25519) verifiziert diese Klasse dagegen mit einer
 * eigenen, kleinen Implementierung <b>gegen denselben vorberechneten
 * SHA-256-Digest</b>, den auch {@link HsmBackedPGPContentSignerBuilder} beim
 * Signieren an die HSM uebergeben hat - reines "pure EdDSA" ueber die
 * Rohnachricht (der eigentliche OpenPGP-Standardfall) waere mit Bouncy
 * Castles unveraendertem Standard-Verifier <b>nicht</b> kompatibel zu den von
 * dieser PoC erzeugten Signaturen, da {@code HsmSignatureRequest} bewusst
 * einen vorberechneten Digest statt der Rohnachricht an die HSM uebergibt
 * (siehe dortiges JavaDoc sowie Open Question 1 der Feature-Spezifikation
 * "openpgp-signing"). Mit Standard-OpenPGP-Tooling (gpg, unveraendertes BC)
 * erzeugte oder erwartete Ed25519-Signaturen sind daher <b>nicht</b>
 * interoperabel mit dieser PoC - eine dokumentierte, aus dem bereits
 * abgeschlossenen Port-Zuschnitt resultierende Einschraenkung dieser
 * Iteration (siehe docs/technical).</p>
 */
final class HsmBackedPGPContentVerifierBuilderProvider implements PGPContentVerifierBuilderProvider {

    private final JcaPGPContentVerifierBuilderProvider standardProvider = new JcaPGPContentVerifierBuilderProvider();

    @Override
    public PGPContentVerifierBuilder get(int keyAlgorithm, int hashAlgorithm) throws PGPException {
        if (keyAlgorithm == PublicKeyAlgorithmTags.Ed25519) {
            return new Ed25519DigestVerifierBuilder(hashAlgorithm);
        }
        return standardProvider.get(keyAlgorithm, hashAlgorithm);
    }

    private static final class Ed25519DigestVerifierBuilder implements PGPContentVerifierBuilder {

        private final int hashAlgorithm;

        private Ed25519DigestVerifierBuilder(int hashAlgorithm) {
            this.hashAlgorithm = hashAlgorithm;
        }

        @Override
        public PGPContentVerifier build(PGPPublicKey publicKey) throws PGPException {
            byte[] rawPoint = publicKey.getPublicKeyPacket().getKey().getEncoded();
            var jcaPublicKey = ed25519PublicKeyFromRawBytes(rawPoint);
            MessageDigest digest;
            try {
                digest = MessageDigest.getInstance("SHA-256");
            } catch (NoSuchAlgorithmException e) {
                throw new PGPException("SHA-256 ist auf dieser JVM nicht verfuegbar", e);
            }
            var outputStream = new DigestOutputStream(OutputStream.nullOutputStream(), digest);

            return new PGPContentVerifier() {
                @Override
                public OutputStream getOutputStream() {
                    return outputStream;
                }

                @Override
                public int getHashAlgorithm() {
                    return hashAlgorithm;
                }

                @Override
                public int getKeyAlgorithm() {
                    return PublicKeyAlgorithmTags.Ed25519;
                }

                @Override
                public long getKeyID() {
                    return publicKey.getKeyID();
                }

                @Override
                public boolean verify(byte[] expectedSignature) {
                    try {
                        var signature = Signature.getInstance("Ed25519");
                        signature.initVerify(jcaPublicKey);
                        signature.update(digest.digest());
                        return signature.verify(expectedSignature);
                    } catch (GeneralSecurityException e) {
                        return false;
                    }
                }
            };
        }
    }

    /**
     * Baut einen {@code java.security.PublicKey} aus der rohen, nativen
     * 32-Byte-Ed25519-Punktkodierung (RFC 8032: little-endian Y-Koordinate,
     * oberstes Bit des letzten Bytes kodiert das Vorzeichen der
     * X-Koordinate) - reine JDK-API, keine Bouncy-Castle-Krypto-Implementierung.
     */
    static java.security.PublicKey ed25519PublicKeyFromRawBytes(byte[] rawPoint) throws PGPException {
        try {
            byte[] littleEndianY = rawPoint.clone();
            boolean xOdd = (littleEndianY[31] & 0x80) != 0;
            littleEndianY[31] &= 0x7f;
            byte[] bigEndianY = new byte[32];
            for (int i = 0; i < 32; i++) {
                bigEndianY[i] = littleEndianY[31 - i];
            }
            var y = new java.math.BigInteger(1, bigEndianY);
            var point = new EdECPoint(xOdd, y);
            var spec = new EdECPublicKeySpec(NamedParameterSpec.ED25519, point);
            return KeyFactory.getInstance("Ed25519").generatePublic(spec);
        } catch (GeneralSecurityException e) {
            throw new PGPException("Ungueltiges Ed25519-Schluesselmaterial: " + e.getMessage(), e);
        }
    }
}
