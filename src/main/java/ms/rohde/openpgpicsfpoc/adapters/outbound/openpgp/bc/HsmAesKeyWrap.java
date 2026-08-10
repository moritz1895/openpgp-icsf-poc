package ms.rohde.openpgpicsfpoc.adapters.outbound.openpgp.bc;

import java.util.Arrays;
import java.util.Objects;
import ms.rohde.openpgpicsfpoc.core.domain.ByteSequence;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmAesCipherMode;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmAesEncryption;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmAesEncryptionExecutor;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmCipherOperation;

/**
 * RFC-3394-AES-Schluesselverpackung (Key Wrap), bei der jeder einzelne
 * AES-Blockschritt ueber die HSM ({@link HsmAesEncryptionExecutor} mit
 * {@link HsmAesCipherMode#ECB} auf genau einem 16-Byte-Block) ausgefuehrt
 * wird - exakt dasselbe Baustein-Muster, das diese PoC auch fuer den
 * OpenPGP-CFB-Resync verwendet (siehe Projektplan, Abschnitt
 * "Hsm-Primitives"). Der abgeleitete Schluessel-Wickel-Schluessel (KEK) ist
 * ephemer (aus einem einmaligen ECDH-Shared-Secret abgeleitet, nie
 * persistiert) und wird daher - wie der AES-Sitzungsschluessel selbst - im
 * "Clear-Key"-Betriebsmodus der {@code HsmAesEncryption}-Primitive
 * uebergeben.
 */
final class HsmAesKeyWrap {

    private static final long IV = 0xA6A6A6A6A6A6A6A6L;
    private static final int BLOCK_LENGTH = 16;
    private static final int HALF_BLOCK_LENGTH = 8;

    private final HsmAesEncryptionExecutor executor;
    private final byte[] kek;

    HsmAesKeyWrap(HsmAesEncryptionExecutor executor, byte[] kek) {
        this.executor = Objects.requireNonNull(executor, "executor darf nicht null sein");
        this.kek = kek.clone();
    }

    byte[] wrap(byte[] plaintext) {
        if (plaintext.length % HALF_BLOCK_LENGTH != 0 || plaintext.length == 0) {
            throw new IllegalArgumentException("plaintext muss ein Vielfaches von 8 Byte und nicht leer sein");
        }
        int n = plaintext.length / HALF_BLOCK_LENGTH;
        byte[] a = longToBytes(IV);
        byte[][] r = new byte[n][];
        for (int i = 0; i < n; i++) {
            r[i] = Arrays.copyOfRange(plaintext, i * HALF_BLOCK_LENGTH, (i + 1) * HALF_BLOCK_LENGTH);
        }

        for (int j = 0; j < 6; j++) {
            for (int i = 0; i < n; i++) {
                byte[] block = concat(a, r[i]);
                byte[] b = aesEcbEncryptBlock(block);
                long t = (long) n * j + (i + 1);
                a = xor(Arrays.copyOfRange(b, 0, HALF_BLOCK_LENGTH), longToBytes(t));
                r[i] = Arrays.copyOfRange(b, HALF_BLOCK_LENGTH, BLOCK_LENGTH);
            }
        }

        byte[] output = new byte[(n + 1) * HALF_BLOCK_LENGTH];
        System.arraycopy(a, 0, output, 0, HALF_BLOCK_LENGTH);
        for (int i = 0; i < n; i++) {
            System.arraycopy(r[i], 0, output, (i + 1) * HALF_BLOCK_LENGTH, HALF_BLOCK_LENGTH);
        }
        return output;
    }

    byte[] unwrap(byte[] wrapped) {
        if (wrapped.length % HALF_BLOCK_LENGTH != 0 || wrapped.length < 2 * HALF_BLOCK_LENGTH) {
            throw new IllegalArgumentException("wrapped hat eine ungueltige Laenge");
        }
        int n = wrapped.length / HALF_BLOCK_LENGTH - 1;
        byte[] a = Arrays.copyOfRange(wrapped, 0, HALF_BLOCK_LENGTH);
        byte[][] r = new byte[n][];
        for (int i = 0; i < n; i++) {
            r[i] = Arrays.copyOfRange(
                    wrapped, (i + 1) * HALF_BLOCK_LENGTH, (i + 2) * HALF_BLOCK_LENGTH);
        }

        for (int j = 5; j >= 0; j--) {
            for (int i = n - 1; i >= 0; i--) {
                long t = (long) n * j + (i + 1);
                byte[] aXorT = xor(a, longToBytes(t));
                byte[] block = concat(aXorT, r[i]);
                byte[] b = aesEcbDecryptBlock(block);
                a = Arrays.copyOfRange(b, 0, HALF_BLOCK_LENGTH);
                r[i] = Arrays.copyOfRange(b, HALF_BLOCK_LENGTH, BLOCK_LENGTH);
            }
        }

        if (bytesToLong(a) != IV) {
            throw new HsmAesKeyUnwrapIntegrityException();
        }

        byte[] output = new byte[n * HALF_BLOCK_LENGTH];
        for (int i = 0; i < n; i++) {
            System.arraycopy(r[i], 0, output, i * HALF_BLOCK_LENGTH, HALF_BLOCK_LENGTH);
        }
        return output;
    }

    private byte[] aesEcbEncryptBlock(byte[] block) {
        return aesEcbBlock(block, HsmCipherOperation.ENCRYPT);
    }

    private byte[] aesEcbDecryptBlock(byte[] block) {
        return aesEcbBlock(block, HsmCipherOperation.DECRYPT);
    }

    private byte[] aesEcbBlock(byte[] block, HsmCipherOperation operation) {
        var request = HsmAesEncryption.builder()
                .sessionKey(ByteSequence.of(kek))
                .cipherMode(HsmAesCipherMode.ECB)
                .operation(operation)
                .input(ByteSequence.of(block))
                .build();
        return executor.execute(request).output().value();
    }

    private static byte[] concat(byte[] left, byte[] right) {
        byte[] result = new byte[left.length + right.length];
        System.arraycopy(left, 0, result, 0, left.length);
        System.arraycopy(right, 0, result, left.length, right.length);
        return result;
    }

    private static byte[] xor(byte[] left, byte[] right) {
        byte[] result = new byte[left.length];
        for (int i = 0; i < left.length; i++) {
            result[i] = (byte) (left[i] ^ right[i]);
        }
        return result;
    }

    private static byte[] longToBytes(long value) {
        byte[] result = new byte[HALF_BLOCK_LENGTH];
        for (int i = HALF_BLOCK_LENGTH - 1; i >= 0; i--) {
            result[i] = (byte) (value & 0xff);
            value >>>= 8;
        }
        return result;
    }

    private static long bytesToLong(byte[] bytes) {
        long value = 0;
        for (byte b : bytes) {
            value = (value << 8) | (b & 0xffL);
        }
        return value;
    }
}
