package ms.rohde.openpgpicsfpoc.adapters.outbound.openpgp.bc;

import java.util.Arrays;
import java.util.Objects;
import ms.rohde.openpgpicsfpoc.core.domain.ByteSequence;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmAesCipherMode;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmAesEncryption;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmAesEncryptionExecutor;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmAesEncryptionRequest;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmCipherOperation;

/**
 * Gemeinsame Bausteine fuer das moderne, AEAD-basierte Verschluesselungsprofil
 * (SEIPD v2, RFC 9580 Section 5.13.2): Chunk-Groesse, Nonce-Ableitung je
 * Chunk sowie die einzelne AES-256-GCM-Chunk-Operation, die fuer jeden
 * echten Daten-Chunk sowie fuer den abschliessenden,
 * laengenauthentisierenden Nachrichten-Tag (RFC 9580 Section 5.13.2, ueber
 * <i>leeren</i> Klartext berechnet - siehe {@link HsmAesEncryptionRequest}
 * fuer die dafuer vorgesehene GCM-Ausnahme von der sonst geltenden
 * Nicht-leer-Regel fuer {@code input}) ueber {@link HsmAesEncryptionExecutor}
 * mit {@link HsmAesCipherMode#GCM} ausgefuehrt wird (siehe Projektplan,
 * Abschnitt "Hsm-Primitives"). Es findet an keiner Stelle dieser Klasse eine
 * lokale symmetrische Verschluesselung mit echtem Schluesselmaterial statt.
 */
final class HsmAeadChunkCodec {

    static final int TAG_LENGTH = 16;

    private final HsmAesEncryptionExecutor executor;
    private final byte[] messageKey;
    private final byte[] iv;
    private final byte[] aaData;

    HsmAeadChunkCodec(HsmAesEncryptionExecutor executor, byte[] messageKey, byte[] iv, byte[] aaData) {
        this.executor = executor;
        this.messageKey = messageKey.clone();
        this.iv = iv.clone();
        this.aaData = aaData.clone();
    }

    static long chunkLength(int chunkSizeOctet) {
        return 1L << (chunkSizeOctet + 6);
    }

    byte[] nonceForChunk(long chunkIndex) {
        byte[] nonce = iv.clone();
        byte[] chunkIndexBytes = longToBigEndianBytes(chunkIndex);
        int offset = nonce.length - 8;
        for (int i = 0; i < 8; i++) {
            nonce[offset + i] ^= chunkIndexBytes[i];
        }
        return nonce;
    }

    byte[] finalTagAssociatedData(long totalPlaintextBytes) {
        byte[] result = Arrays.copyOf(aaData, aaData.length + 8);
        System.arraycopy(longToBigEndianBytes(totalPlaintextBytes), 0, result, aaData.length, 8);
        return result;
    }

    byte[] encryptChunk(byte[] plaintext, long chunkIndex) {
        var request = HsmAesEncryption.builder()
                .sessionKey(ByteSequence.of(messageKey))
                .cipherMode(HsmAesCipherMode.GCM)
                .operation(HsmCipherOperation.ENCRYPT)
                .input(ByteSequence.of(plaintext))
                .initializationVector(ByteSequence.of(nonceForChunk(chunkIndex)))
                .additionalAuthenticatedData(ByteSequence.of(aaData))
                .build();
        var result = executor.execute(request);
        return result.output().concat(Objects.requireNonNull(result.authenticationTag())).value();
    }

    byte[] decryptChunk(byte[] ciphertextWithTag, long chunkIndex) {
        int ciphertextLength = ciphertextWithTag.length - TAG_LENGTH;
        var ciphertext = Arrays.copyOfRange(ciphertextWithTag, 0, ciphertextLength);
        var tag = Arrays.copyOfRange(ciphertextWithTag, ciphertextLength, ciphertextWithTag.length);
        try {
            var request = HsmAesEncryption.builder()
                    .sessionKey(ByteSequence.of(messageKey))
                    .cipherMode(HsmAesCipherMode.GCM)
                    .operation(HsmCipherOperation.DECRYPT)
                    .input(ByteSequence.of(ciphertext))
                    .initializationVector(ByteSequence.of(nonceForChunk(chunkIndex)))
                    .additionalAuthenticatedData(ByteSequence.of(aaData))
                    .authenticationTag(ByteSequence.of(tag))
                    .build();
            return executor.execute(request).output().value();
        } catch (RuntimeException e) {
            throw new OpenPgpDecryptionFailedException("AEAD-Integritaetspruefung fehlgeschlagen", e);
        }
    }

    /**
     * Verschluesselt den abschliessenden, laengenauthentisierenden
     * Nachrichten-Tag ueber leeren Klartext (RFC 9580 Section 5.13.2) - wie
     * jede echte Chunk-Operation ueber {@link HsmAesEncryptionExecutor}
     * ausgefuehrt (leerer {@code input} ist fuer {@link HsmAesCipherMode#GCM}
     * explizit zulaessig, siehe {@link HsmAesEncryptionRequest}).
     */
    byte[] encryptFinalTag(long chunkIndexAfterLast, long totalPlaintextBytes) {
        var request = HsmAesEncryption.builder()
                .sessionKey(ByteSequence.of(messageKey))
                .cipherMode(HsmAesCipherMode.GCM)
                .operation(HsmCipherOperation.ENCRYPT)
                .input(ByteSequence.empty())
                .initializationVector(ByteSequence.of(nonceForChunk(chunkIndexAfterLast)))
                .additionalAuthenticatedData(ByteSequence.of(finalTagAssociatedData(totalPlaintextBytes)))
                .build();
        var result = executor.execute(request);
        return Objects.requireNonNull(result.authenticationTag()).value();
    }

    /**
     * Prueft den abschliessenden Nachrichten-Tag - Gegenstueck zu
     * {@link #encryptFinalTag(long, long)}, ebenfalls ueber
     * {@link HsmAesEncryptionExecutor} ausgefuehrt.
     */
    void verifyFinalTag(byte[] tag, long chunkIndexAfterLast, long totalPlaintextBytes) {
        try {
            var request = HsmAesEncryption.builder()
                    .sessionKey(ByteSequence.of(messageKey))
                    .cipherMode(HsmAesCipherMode.GCM)
                    .operation(HsmCipherOperation.DECRYPT)
                    .input(ByteSequence.empty())
                    .initializationVector(ByteSequence.of(nonceForChunk(chunkIndexAfterLast)))
                    .additionalAuthenticatedData(ByteSequence.of(finalTagAssociatedData(totalPlaintextBytes)))
                    .authenticationTag(ByteSequence.of(tag))
                    .build();
            executor.execute(request);
        } catch (RuntimeException e) {
            throw new OpenPgpDecryptionFailedException("AEAD-Integritaetspruefung des Nachrichten-Tags fehlgeschlagen", e);
        }
    }

    private static byte[] longToBigEndianBytes(long value) {
        byte[] result = new byte[8];
        for (int i = 7; i >= 0; i--) {
            result[i] = (byte) (value & 0xff);
            value >>>= 8;
        }
        return result;
    }
}
