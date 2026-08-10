package ms.rohde.openpgpicsfpoc.adapters.outbound.openpgp.bc;

import ms.rohde.openpgpicsfpoc.core.domain.ByteSequence;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmAesCipherMode;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmAesEncryption;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmAesEncryptionExecutor;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmCipherOperation;

/**
 * Plain-CFB-Betriebsmodus (volle Blockrueckkopplung, NIST SP 800-38A) mit
 * Null-Initialisierungsvektor fuer das klassische, integritaetsgeschuetzte
 * Verschluesselungsprofil (SEIPD v1, RFC 4880).
 *
 * <p><b>Wichtig:</b> SEIPD v1 (mit MDC-Trailer) verwendet in Bouncy Castles
 * eigener Referenzimplementierung ({@code BcUtil.createStreamCipher(...,
 * withIntegrityPacket=true, ...)}) bewusst <b>keine</b> spezielle
 * "OpenPGP-CFB-mit-Resync"-Konstruktion (die dortige {@code OpenPGPCFBBlockCipher}-Klasse
 * wird nur fuer das aeltere, MDC-lose SED-Paketformat verwendet, das nicht
 * Teil des Scopes dieser PoC ist) - stattdessen ein gewoehnlicher
 * CFB-Modus mit voller Blockrueckkopplung und einem Null-IV
 * ({@code new ParametersWithIV(key, new byte[blockSize])}). Jede
 * Blockchiffre-Operation ({@code AES_encrypt(K, Rueckkopplungsregister)})
 * laeuft ueber {@link HsmAesEncryptionExecutor} mit {@link HsmAesCipherMode#ECB}
 * auf genau einem 16-Byte-Block (siehe Projektplan, Abschnitt
 * "Hsm-Primitives") - die zugrunde liegende Blockchiffre wird dabei sowohl
 * beim Ver- als auch beim Entschluesseln des Datenstroms im
 * Verschluesselungsmodus aufgerufen (Eigenschaft von CFB als
 * selbstsynchronisierendem Modus), daher ausschliesslich
 * {@link HsmCipherOperation#ENCRYPT}-Aufrufe gegen die HSM.
 */
final class HsmCfbEngine {

    private static final int BLOCK_LENGTH = 16;

    private final HsmAesEncryptionExecutor executor;
    private final byte[] sessionKey;
    private byte[] feedbackRegister = new byte[BLOCK_LENGTH];

    HsmCfbEngine(HsmAesEncryptionExecutor executor, byte[] sessionKey) {
        this.executor = executor;
        this.sessionKey = sessionKey.clone();
    }

    /** Verschluesselt einen (ggf. unvollstaendigen) Block; das Rueckkopplungsregister wird mit dem erzeugten Chiffretext aktualisiert. */
    byte[] encryptBlock(byte[] plaintext, int length) {
        byte[] keystream = hsmEcbEncrypt(feedbackRegister);
        byte[] ciphertext = new byte[length];
        for (int i = 0; i < length; i++) {
            ciphertext[i] = (byte) (plaintext[i] ^ keystream[i]);
        }
        updateFeedbackRegister(ciphertext, length);
        return ciphertext;
    }

    /** Entschluesselt einen (ggf. unvollstaendigen) Block; das Rueckkopplungsregister wird mit dem gelesenen Chiffretext aktualisiert. */
    byte[] decryptBlock(byte[] ciphertext, int length) {
        byte[] keystream = hsmEcbEncrypt(feedbackRegister);
        byte[] plaintext = new byte[length];
        for (int i = 0; i < length; i++) {
            plaintext[i] = (byte) (ciphertext[i] ^ keystream[i]);
        }
        updateFeedbackRegister(ciphertext, length);
        return plaintext;
    }

    private void updateFeedbackRegister(byte[] block, int length) {
        byte[] newRegister = new byte[BLOCK_LENGTH];
        System.arraycopy(block, 0, newRegister, 0, length);
        feedbackRegister = newRegister;
    }

    private byte[] hsmEcbEncrypt(byte[] block) {
        var request = HsmAesEncryption.builder()
                .sessionKey(ByteSequence.of(sessionKey))
                .cipherMode(HsmAesCipherMode.ECB)
                .operation(HsmCipherOperation.ENCRYPT)
                .input(ByteSequence.of(block))
                .build();
        return executor.execute(request).output().value();
    }

    static int blockLength() {
        return BLOCK_LENGTH;
    }
}
