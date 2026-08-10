package ms.rohde.openpgpicsfpoc.adapters.outbound.openpgp.bc;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmAesEncryptionExecutor;
import org.bouncycastle.bcpg.SymmetricEncIntegrityPacket;
import org.bouncycastle.openpgp.operator.PGPDataDecryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;

/**
 * Von allen HSM-gestuetzten {@code PublicKeyDataDecryptorFactory}-Implementierungen
 * dieser Bridge gemeinsam genutzte Bausteine zum Entschluesseln der
 * symmetrisch geschuetzten Nutzlast - unabhaengig davon, welcher
 * asymmetrische Algorithmus den Sitzungsschluessel aufgeschlossen hat (siehe
 * {@link HsmBackedPGPDataEncryptorBuilder} fuer das jeweilige
 * Verschluesselungs-Gegenstueck).
 */
final class HsmSymmetricDecryptorSupport {

    private HsmSymmetricDecryptorSupport() {}

    /** Legacy-Profil (SEIPD v1): Plain-CFB mit Null-IV ueber Einzelblock-HSM-Aufrufe (siehe {@link HsmCfbEngine}). */
    static PGPDataDecryptor createCfbDecryptor(HsmAesEncryptionExecutor executor, byte[] sessionKey) {
        return new PGPDataDecryptor() {
            @Override
            public InputStream getInputStream(InputStream in) {
                return new HsmCfbInputStream(in, new HsmCfbEngine(executor, sessionKey));
            }

            @Override
            public int getBlockSize() {
                return HsmCfbEngine.blockLength();
            }

            @Override
            public PGPDigestCalculator getIntegrityCalculator() {
                return new LocalSha1DigestCalculator();
            }
        };
    }

    /** Modernes Profil (SEIPD v2/AEAD): Chunk-weise AES-256-GCM ueber HSM. */
    static PGPDataDecryptor createAeadDecryptor(
            HsmAesEncryptionExecutor executor, SymmetricEncIntegrityPacket seipd, byte[] sessionKey) {
        byte[] hkdfInfo = seipd.getAAData();
        int keyLength = Rfc6637KeyDerivation.keyLength(seipd.getCipherAlgorithm());
        int ivLength = 12;
        byte[] messageKeyAndIv = Rfc6637KeyDerivation.aeadMessageKeyAndIvMaterial(
                sessionKey, seipd.getSalt(), hkdfInfo, keyLength + ivLength - 8);
        byte[] messageKey = Arrays.copyOfRange(messageKeyAndIv, 0, keyLength);
        byte[] iv = Arrays.copyOf(Arrays.copyOfRange(messageKeyAndIv, keyLength, messageKeyAndIv.length), ivLength);
        var codec = new HsmAeadChunkCodec(executor, messageKey, iv, hkdfInfo);
        long chunkLength = HsmAeadChunkCodec.chunkLength(seipd.getChunkSize());

        return new PGPDataDecryptor() {
            @Override
            public InputStream getInputStream(InputStream in) {
                return new ByteArrayInputStream(decryptAll(in));
            }

            @Override
            public int getBlockSize() {
                return 16;
            }

            @Override
            public PGPDigestCalculator getIntegrityCalculator() {
                return null;
            }

            private byte[] decryptAll(InputStream in) {
                byte[] all;
                try {
                    all = in.readAllBytes();
                } catch (IOException e) {
                    throw new OpenPgpDecryptionFailedException("Lesen der AEAD-Nutzlast fehlgeschlagen", e);
                }

                int recordLength = (int) chunkLength + HsmAeadChunkCodec.TAG_LENGTH;
                int chunkBytesTotal = all.length - HsmAeadChunkCodec.TAG_LENGTH;
                if (chunkBytesTotal < 0) {
                    throw new OpenPgpDecryptionFailedException("AEAD-Nutzlast ist kuerzer als der Nachrichten-Tag");
                }

                var plaintext = new ByteArrayOutputStream();
                long chunkIndex = 0;
                int offset = 0;
                while (offset < chunkBytesTotal) {
                    int thisRecordLength = Math.min(recordLength, chunkBytesTotal - offset);
                    byte[] record = Arrays.copyOfRange(all, offset, offset + thisRecordLength);
                    plaintext.writeBytes(codec.decryptChunk(record, chunkIndex));
                    offset += thisRecordLength;
                    chunkIndex++;
                }

                byte[] finalTag = Arrays.copyOfRange(all, chunkBytesTotal, all.length);
                codec.verifyFinalTag(finalTag, chunkIndex, plaintext.size());

                return plaintext.toByteArray();
            }
        };
    }
}
