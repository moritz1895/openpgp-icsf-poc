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
 * dieser Bridge gemeinsam genutzter Baustein zum Entschluesseln der
 * symmetrisch AEAD-geschuetzten Nutzlast (SEIPD v2, RFC 9580) - unabhaengig
 * davon, welcher asymmetrische Algorithmus den Sitzungsschluessel
 * aufgeschlossen hat (siehe {@link HsmBackedPGPDataEncryptorBuilder} fuer
 * das Verschluesselungs-Gegenstueck).
 */
final class HsmSymmetricDecryptorSupport {

    private HsmSymmetricDecryptorSupport() {}

    /**
     * Baut einen {@link PGPDataDecryptor} fuer SEIPD v2/AEAD: leitet Nachrichtenschluessel
     * und Nonce-Praefix per HKDF-SHA256 aus Sitzungsschluessel und im Paket enthaltenem
     * Salt ab (RFC 9580 Section 5.13.2) und liest anschliessend Chunk-weise AES-256-GCM-Blöcke
     * ueber {@link HsmAeadChunkCodec}.
     *
     * <p>Anders als ein Klartext-Stream kann die AEAD-Nutzlast nicht Chunk-fuer-Chunk an den
     * Aufrufer durchgereicht werden, bevor der abschliessende, laengenauthentisierende
     * Nachrichten-Tag (letztes "Chunk", siehe {@link HsmAeadChunkCodec#verifyFinalTag}) geprueft
     * ist - sonst koennte ein Angreifer die Nachricht unbemerkt kuerzen (Truncation-Angriff).
     * {@link #createAeadDecryptor} liest daher den kompletten Ciphertext vorab ein, entschluesselt
     * und verifiziert alle Chunks inklusive Nachrichten-Tag, und liefert erst danach den fertigen
     * Klartext als {@link ByteArrayInputStream} zurueck.</p>
     */
    static PGPDataDecryptor createAeadDecryptor(
            HsmAesEncryptionExecutor executor, SymmetricEncIntegrityPacket seipd, byte[] sessionKey) {
        byte[] hkdfInfo = seipd.getAAData();
        int keyLength = Rfc6637KeyDerivation.keyLength(seipd.getCipherAlgorithm());
        int ivLength = 12;
        byte[] messageKeyAndIv = Rfc6637KeyDerivation.aeadMessageKeyAndIvMaterial(
                sessionKey, seipd.getSalt(), hkdfInfo, keyLength + ivLength - 8);
        byte[] messageKey = Arrays.copyOfRange(messageKeyAndIv, 0, keyLength);
        byte[] iv = Arrays.copyOf(Arrays.copyOfRange(messageKeyAndIv, keyLength, messageKeyAndIv.length), ivLength);
        HsmAeadChunkCodec codec = new HsmAeadChunkCodec(executor, messageKey, iv, hkdfInfo);
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

            /**
             * Liest die vollstaendige Ciphertext-Wire-Darstellung (fortlaufende
             * {@code chunkLength + TAG_LENGTH}-Byte-Records, gefolgt vom
             * {@code TAG_LENGTH}-Byte-langen Nachrichten-Tag), entschluesselt jeden
             * Record einzeln ueber {@link HsmAeadChunkCodec#decryptChunk} und haengt
             * den jeweils zurueckgegebenen Klartext-Chunk an - siehe Klassen-JavaDoc
             * dieser Methode zur Begruendung, warum das nicht streamend erfolgen kann.
             */
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

                ByteArrayOutputStream plaintext = new ByteArrayOutputStream();
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
