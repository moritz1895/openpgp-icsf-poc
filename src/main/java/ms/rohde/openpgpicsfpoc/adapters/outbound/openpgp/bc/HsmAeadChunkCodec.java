package ms.rohde.openpgpicsfpoc.adapters.outbound.openpgp.bc;

import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Objects;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import ms.rohde.openpgpicsfpoc.core.domain.ByteSequence;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmAesCipherMode;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmAesEncryption;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmAesEncryptionExecutor;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmCipherOperation;

/**
 * Gemeinsame Bausteine fuer das moderne, AEAD-basierte Verschluesselungsprofil
 * (SEIPD v2, RFC 9580 Section 5.13.2): Chunk-Groesse, Nonce-Ableitung je
 * Chunk sowie die einzelne AES-256-GCM-Chunk-Operation, die fuer jeden
 * echten Daten-Chunk ueber {@link HsmAesEncryptionExecutor} mit
 * {@link HsmAesCipherMode#GCM} ausgefuehrt wird (siehe Projektplan, Abschnitt
 * "Hsm-Primitives").
 *
 * <p><b>Bekannte, dokumentierte Einschraenkung des abschliessenden
 * Nachrichten-Tags:</b> RFC 9580 verlangt zusaetzlich zu den Daten-Chunks
 * einen abschliessenden, laengenauthentisierenden Tag, der ueber
 * <i>leeren</i> Klartext berechnet wird (Section 5.13.2). Der bereits
 * abgeschlossene {@code HsmAesEncryptionRequest}-Port (siehe
 * {@code ports.outbound.hsm.HsmAesEncryptionRequest}, ausserhalb des Scopes
 * dieser Iteration) lehnt leere {@code input}-Werte fuer <b>jeden</b>
 * Cipher-Modus grundsaetzlich ab und kann diese eine, strukturell
 * unvermeidbare Operation daher nicht abbilden. Da der dabei verwendete
 * Nachrichtenschluessel ohnehin ephemeres, HKDF-abgeleitetes, nie
 * persistiertes Material ist - vom Port selbst bereits als
 * "Clear-Key"-geeignet eingestuft (siehe JavaDoc auf
 * {@code HsmAesEncryptionRequest}) -, wird ausschliesslich dieser eine
 * Sonderfall lokal per {@code javax.crypto.Cipher} berechnet statt ueber die
 * HSM-Primitive; alle echten Nutzdaten-Chunks durchlaufen weiterhin
 * ausnahmslos die HSM. Diese Einschraenkung ist fuer eine spaetere
 * Port-Erweiterung (z. B. GCM-Ausnahme von der Nicht-leer-Regel) in
 * docs/technical zu dokumentieren.</p>
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
     * Nachrichten-Tag ueber leeren Klartext (RFC 9580 Section 5.13.2) - siehe
     * Klassen-JavaDoc zur Begruendung, warum dieser eine Sonderfall lokal
     * statt ueber die HSM-Primitive berechnet wird.
     */
    byte[] encryptFinalTag(long chunkIndexAfterLast, long totalPlaintextBytes) {
        try {
            var cipher = Cipher.getInstance("AES/GCM/NoPadding");
            var spec = new GCMParameterSpec(TAG_LENGTH * 8, nonceForChunk(chunkIndexAfterLast));
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(messageKey, "AES"), spec);
            cipher.updateAAD(finalTagAssociatedData(totalPlaintextBytes));
            return cipher.doFinal();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Berechnung des abschliessenden AEAD-Tags fehlgeschlagen", e);
        }
    }

    /**
     * Prueft den abschliessenden Nachrichten-Tag - lokales Gegenstueck zu
     * {@link #encryptFinalTag(long, long)}.
     */
    void verifyFinalTag(byte[] tag, long chunkIndexAfterLast, long totalPlaintextBytes) {
        try {
            var cipher = Cipher.getInstance("AES/GCM/NoPadding");
            var spec = new GCMParameterSpec(TAG_LENGTH * 8, nonceForChunk(chunkIndexAfterLast));
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(messageKey, "AES"), spec);
            cipher.updateAAD(finalTagAssociatedData(totalPlaintextBytes));
            cipher.doFinal(tag);
        } catch (GeneralSecurityException e) {
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
