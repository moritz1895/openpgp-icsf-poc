package ms.rohde.openpgpicsfpoc.adapters.outbound.openpgp.bc;

import java.io.OutputStream;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmAesEncryptionExecutor;
import org.bouncycastle.bcpg.SymmetricEncIntegrityPacket;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.operator.PGPAEADDataEncryptor;
import org.bouncycastle.openpgp.operator.PGPDataEncryptor;
import org.bouncycastle.openpgp.operator.PGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;

/**
 * HSM-gestuetzter {@link PGPDataEncryptorBuilder}: erzeugt die symmetrische
 * Nutzlastverschluesselung fuer das einzige von dieser PoC unterstuetzte
 * Verschluesselungsprofil, SEIPD v2/AEAD (RFC 9580). {@link #build(byte[], byte[])}
 * leitet den Nachrichtenschluessel und das Nonce-Praefix lokal per HKDF-SHA256
 * aus Sitzungsschluessel und Salt ab (RFC 9580 Section 5.13.2) und verschluesselt
 * Chunk-weise per AES-256-GCM ueber {@code HsmAesEncryption}-Aufrufe mit
 * {@code cipherMode(GCM)}.
 *
 * <p>Das klassische, MDC-basierte Profil (SEIPD v1, RFC 4880, Plain-CFB) wird
 * bewusst nicht unterstuetzt (siehe GitHub-Issue "korrekturen zur
 * implementierung": ein zusaetzliches, kryptographisch schwaecheres Profil
 * ohne Mehrwert fuer diese PoC haette nur unnoetigen Implementierungs- und
 * Pflegeaufwand bedeutet) - {@link #build(byte[])} wird von Bouncy Castle nur
 * fuer dieses Profil aufgerufen und wirft daher immer eine {@link PGPException}.</p>
 */
final class HsmBackedPGPDataEncryptorBuilder implements PGPDataEncryptorBuilder {

    private final int cipherAlgorithm;
    private final HsmAesEncryptionExecutor executor;
    private final SecureRandom secureRandom;

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
        if (!withIntegrityPacket) {
            throw new IllegalArgumentException(
                    "Nachrichten ohne Integritaetsschutz werden von dieser PoC nicht unterstuetzt - "
                            + "nur SEIPD v2/AEAD");
        }
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
                        + "Feature-Spezifikation: nur SEIPD v2/AEAD)");
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
        throw new PGPException(
                "SEIPD v1 (Plain-CFB+MDC) wird von dieser PoC nicht unterstuetzt - siehe Klassen-JavaDoc "
                        + "(nur SEIPD v2/AEAD)");
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
        byte[] messageKey = Arrays.copyOfRange(messageKeyAndIv, 0, keyLength);
        byte[] iv = Arrays.copyOf(Arrays.copyOfRange(messageKeyAndIv, keyLength, messageKeyAndIv.length), ivLength);
        return new AeadDataEncryptor(messageKey, iv, hkdfInfo);
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
            HsmAeadChunkCodec codec = new HsmAeadChunkCodec(executor, messageKey, iv, aaData);
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
