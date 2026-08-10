package ms.rohde.openpgpicsfpoc.adapters.outbound.openpgp.bc;

import java.io.OutputStream;
import java.security.DigestOutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;
import ms.rohde.openpgpicsfpoc.core.domain.ByteSequence;
import ms.rohde.openpgpicsfpoc.core.domain.HsmKeyHandle;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmSignature;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmSignatureAlgorithm;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmSignatureExecutor;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.operator.PGPContentSigner;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;

/**
 * Erzeugt Signaturen fuer RSA-PKCS#1v1.5, ECDSA (klassische Kurven) und
 * natives EdDSA (Ed25519) - das Hashing des Inhalts erfolgt lokal
 * (SHA-256, einheitlich fuer alle drei Algorithmen, siehe JavaDoc auf
 * {@code HsmSignatureRequest}); nur der finale Signaturschritt ueber diesen
 * Digest wird an {@link HsmSignatureExecutor} delegiert.
 *
 * <p>Fuer RSA wird der Digest vor der Uebergabe an die HSM in eine
 * vollstaendige PKCS#1v1.5-DigestInfo-Struktur eingebettet (SHA-256-Algorithmus-ID
 * + Digest); fuer ECDSA wird der rohe 32-Byte-Digest direkt uebergeben (Bouncy
 * Castle wandelt die von der HSM zurueckgegebene DER-kodierte ECDSA-Signatur
 * ueber {@code PGPUtil.dsaSigToMpi} automatisch in die beiden Signatur-MPIs
 * um); fuer EdDSA wird der Digest ebenfalls roh uebergeben (siehe JavaDoc auf
 * {@code HsmSignatureRequest} zur bewussten Abweichung vom "pure
 * EdDSA"-Schema, das ueblicherweise direkt ueber die Rohnachricht statt einen
 * vorberechneten Digest signiert - {@link HsmBackedPGPContentVerifierBuilderProvider}
 * verifiziert konsistent gegen denselben Digest).</p>
 */
final class HsmBackedPGPContentSignerBuilder implements PGPContentSignerBuilder {

    private static final byte[] SHA256_DIGEST_INFO_PREFIX = {
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, (byte) 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00,
        0x04, 0x20
    };

    private final int keyAlgorithmTag;
    private final HsmSignatureExecutor executor;
    private final HsmKeyHandle signerKeyHandle;
    private final long keyId;

    HsmBackedPGPContentSignerBuilder(int keyAlgorithmTag, HsmSignatureExecutor executor, HsmKeyHandle signerKeyHandle, long keyId) {
        this.keyAlgorithmTag = keyAlgorithmTag;
        this.executor = Objects.requireNonNull(executor, "executor darf nicht null sein");
        this.signerKeyHandle = Objects.requireNonNull(signerKeyHandle, "signerKeyHandle darf nicht null sein");
        this.keyId = keyId;
    }

    @Override
    public PGPContentSigner build(int signatureType, PGPPrivateKey ignoredPlaceholderKey) throws PGPException {
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new PGPException("SHA-256 ist auf dieser JVM nicht verfuegbar", e);
        }
        var outputStream = new DigestOutputStream(OutputStream.nullOutputStream(), digest);
        var cachedDigest = new byte[1][];

        return new PGPContentSigner() {
            @Override
            public OutputStream getOutputStream() {
                return outputStream;
            }

            @Override
            public byte[] getSignature() {
                byte[] rawDigest = finalDigest(cachedDigest, digest);
                byte[] hsmInput = keyAlgorithmTag == PublicKeyAlgorithmTags.RSA_GENERAL
                        ? concat(SHA256_DIGEST_INFO_PREFIX, rawDigest)
                        : rawDigest;
                var request = HsmSignature.builder()
                        .keyHandle(signerKeyHandle)
                        .algorithm(hsmSignatureAlgorithm())
                        .digest(ByteSequence.of(hsmInput))
                        .build();
                return executor.execute(request).signature().value();
            }

            @Override
            public byte[] getDigest() {
                return finalDigest(cachedDigest, digest);
            }

            @Override
            public int getType() {
                return signatureType;
            }

            @Override
            public int getHashAlgorithm() {
                return HashAlgorithmTags.SHA256;
            }

            @Override
            public int getKeyAlgorithm() {
                return keyAlgorithmTag;
            }

            @Override
            public long getKeyID() {
                return keyId;
            }
        };
    }

    /**
     * Liefert den finalen Digest genau einmal - {@link MessageDigest#digest()}
     * setzt den internen Zustand zurueck, {@link PGPContentSigner#getSignature()}
     * und {@link PGPContentSigner#getDigest()} muessen aber denselben
     * Digestwert sehen (siehe {@code PGPSignatureGenerator#generate()}, das
     * beide Methoden nacheinander auf demselben {@code PGPContentSigner}
     * aufruft).
     */
    private static byte[] finalDigest(byte[][] cache, MessageDigest digest) {
        if (cache[0] == null) {
            cache[0] = digest.digest();
        }
        return cache[0];
    }

    private HsmSignatureAlgorithm hsmSignatureAlgorithm() {
        return switch (keyAlgorithmTag) {
            case PublicKeyAlgorithmTags.RSA_GENERAL -> HsmSignatureAlgorithm.RSA_PKCS1V15;
            case PublicKeyAlgorithmTags.ECDSA -> HsmSignatureAlgorithm.ECDSA;
            case PublicKeyAlgorithmTags.Ed25519 -> HsmSignatureAlgorithm.EDDSA;
            default -> throw new IllegalArgumentException("Nicht unterstuetzter Signaturalgorithmus: " + keyAlgorithmTag);
        };
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }
}
