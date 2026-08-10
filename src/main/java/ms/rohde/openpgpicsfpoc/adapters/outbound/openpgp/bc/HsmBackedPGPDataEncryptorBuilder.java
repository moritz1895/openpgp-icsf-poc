package ms.rohde.openpgpicsfpoc.adapters.outbound.openpgp.bc;

import java.io.IOException;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.util.Objects;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmAesEncryptionExecutor;
import org.bouncycastle.bcpg.AEADAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricEncIntegrityPacket;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.operator.PGPAEADDataEncryptor;
import org.bouncycastle.openpgp.operator.PGPDataEncryptor;
import org.bouncycastle.openpgp.operator.PGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;

/**
 * HSM-gestuetzter {@link PGPDataEncryptorBuilder}: erzeugt die symmetrische
 * Nutzlastverschluesselung fuer beide Verschluesselungsprofile dieser PoC.
 *
 * <ul>
 *   <li><b>Legacy-Profil (SEIPD v1, RFC 4880):</b> {@link #build(byte[])} liefert
 *       einen {@link PGPDataEncryptor}, dessen Ausgabestrom Plain-CFB mit
 *       Null-IV ueber {@link HsmCfbOutputStream} anwendet (siehe dortiges
 *       JavaDoc), zusammengesetzt aus Einzelblock-{@code HsmAesEncryption}-Aufrufen
 *       mit {@code cipherMode(ECB)}. Der MDC-Trailer wird lokal ueber
 *       {@link LocalSha1DigestCalculator} gebildet.</li>
 *   <li><b>Modernes Profil (SEIPD v2/AEAD, RFC 9580):</b> {@link #build(byte[], byte[])}
 *       leitet den Nachrichtenschluessel und das Nonce-Praefix lokal per HKDF-SHA256
 *       aus Sitzungsschluessel und Salt ab (RFC 9580 Section 5.13.2) und
 *       verschluesselt Chunk-weise per AES-256-GCM ueber
 *       {@code HsmAesEncryption}-Aufrufe mit {@code cipherMode(GCM)}.</li>
 * </ul>
 */
final class HsmBackedPGPDataEncryptorBuilder implements PGPDataEncryptorBuilder {

    private final int cipherAlgorithm;
    private final HsmAesEncryptionExecutor executor;
    private final SecureRandom secureRandom;

    private boolean withIntegrityPacket = true;
    private int aeadAlgorithm = -1;
    private int chunkSizeOctet;

    HsmBackedPGPDataEncryptorBuilder(int cipherAlgorithm, HsmAesEncryptionExecutor executor) {
        this(cipherAlgorithm, executor, new SecureRandom());
    }

    HsmBackedPGPDataEncryptorBuilder(int cipherAlgorithm, HsmAesEncryptionExecutor executor, SecureRandom secureRandom) {
        this.cipherAlgorithm = cipherAlgorithm;
        this.executor = Objects.requireNonNull(executor, "executor darf nicht null sein");
        this.secureRandom = Objects.requireNonNull(secureRandom, "secureRandom darf nicht null sein");
    }

    @Override
    public int getAlgorithm() {
        return cipherAlgorithm;
    }

    @Override
    public int getAeadAlgorithm() {
        return aeadAlgorithm;
    }

    @Override
    public int getChunkSize() {
        return chunkSizeOctet;
    }

    @Override
    public boolean isV5StyleAEAD() {
        return false;
    }

    @Override
    public PGPDataEncryptorBuilder setWithIntegrityPacket(boolean withIntegrityPacket) {
        this.withIntegrityPacket = withIntegrityPacket;
        return this;
    }

    @Override
    public PGPDataEncryptorBuilder setWithAEAD(int aeadAlgorithm, int chunkSize) {
        if (chunkSize < 6) {
            throw new IllegalArgumentException("chunkSize muss mindestens 6 sein");
        }
        this.aeadAlgorithm = aeadAlgorithm;
        this.chunkSizeOctet = chunkSize - 6;
        return this;
    }

    @Override
    public PGPDataEncryptorBuilder setUseV5AEAD() {
        throw new UnsupportedOperationException(
                "Legacy-v5-Style-AEAD (LibrePGP/OCB) ist ausserhalb des Scopes dieser PoC (siehe "
                        + "Feature-Spezifikation: nur SEIPD v1 und SEIPD v2/AEAD)");
    }

    @Override
    public PGPDataEncryptorBuilder setUseV6AEAD() {
        return this;
    }

    @Override
    public SecureRandom getSecureRandom() {
        return secureRandom;
    }

    @Override
    public PGPDataEncryptor build(byte[] keyBytes) throws PGPException {
        if (aeadAlgorithm > 0) {
            throw new PGPException("AEAD-Profil benoetigt Salt - build(byte[], byte[]) verwenden");
        }
        return new CfbMdcDataEncryptor(keyBytes);
    }

    @Override
    public PGPDataEncryptor build(byte[] key, byte[] salt) throws PGPException {
        if (aeadAlgorithm <= 0) {
            throw new PGPException("Kein AEAD-Algorithmus konfiguriert");
        }
        byte[] hkdfInfo =
                SymmetricEncIntegrityPacket.createAAData(SymmetricEncIntegrityPacket.VERSION_2, cipherAlgorithm, aeadAlgorithm, chunkSizeOctet);
        int keyLength = Rfc6637KeyDerivation.keyLength(cipherAlgorithm);
        int ivLength = 12; // GCM
        byte[] messageKeyAndIv =
                Rfc6637KeyDerivation.aeadMessageKeyAndIvMaterial(key, salt, hkdfInfo, keyLength + ivLength - 8);
        byte[] messageKey = java.util.Arrays.copyOfRange(messageKeyAndIv, 0, keyLength);
        byte[] iv = java.util.Arrays.copyOf(java.util.Arrays.copyOfRange(messageKeyAndIv, keyLength, messageKeyAndIv.length), ivLength);
        return new AeadDataEncryptor(messageKey, iv, hkdfInfo);
    }

    private final class CfbMdcDataEncryptor implements PGPDataEncryptor {

        private final byte[] sessionKey;

        CfbMdcDataEncryptor(byte[] sessionKey) {
            this.sessionKey = sessionKey.clone();
        }

        @Override
        public OutputStream getOutputStream(OutputStream out) {
            return new HsmCfbOutputStream(out, new HsmCfbEngine(executor, sessionKey));
        }

        @Override
        public PGPDigestCalculator getIntegrityCalculator() {
            return withIntegrityPacket ? new LocalSha1DigestCalculator() : null;
        }

        @Override
        public int getBlockSize() {
            return HsmCfbEngine.blockLength();
        }
    }

    private final class AeadDataEncryptor implements PGPAEADDataEncryptor {

        private final byte[] messageKey;
        private final byte[] iv;
        private final byte[] aaData;

        AeadDataEncryptor(byte[] messageKey, byte[] iv, byte[] aaData) {
            this.messageKey = messageKey;
            this.iv = iv;
            this.aaData = aaData;
        }

        @Override
        public int getAEADAlgorithm() {
            return aeadAlgorithm;
        }

        @Override
        public int getChunkSize() {
            return chunkSizeOctet;
        }

        @Override
        public byte[] getIV() {
            return iv.clone();
        }

        @Override
        public OutputStream getOutputStream(OutputStream out) {
            var codec = new HsmAeadChunkCodec(executor, messageKey, iv, aaData);
            return new HsmAeadOutputStream(out, codec, chunkSizeOctet);
        }

        @Override
        public PGPDigestCalculator getIntegrityCalculator() {
            return null;
        }

        @Override
        public int getBlockSize() {
            return 16;
        }
    }
}
