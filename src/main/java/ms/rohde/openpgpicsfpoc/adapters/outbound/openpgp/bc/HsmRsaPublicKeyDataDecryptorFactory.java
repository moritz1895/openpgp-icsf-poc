package ms.rohde.openpgpicsfpoc.adapters.outbound.openpgp.bc;

import java.util.Arrays;
import java.util.Objects;
import ms.rohde.openpgpicsfpoc.core.domain.ByteSequence;
import ms.rohde.openpgpicsfpoc.core.domain.HsmKeyHandle;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmAesEncryptionExecutor;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmCipherOperation;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmRsaEncryption;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmRsaEncryptionExecutor;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmRsaEncryptionRequest;
import org.bouncycastle.bcpg.AEADEncDataPacket;
import org.bouncycastle.bcpg.SymmetricEncIntegrityPacket;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSessionKey;
import org.bouncycastle.openpgp.operator.AbstractPublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.PGPDataDecryptor;

/**
 * Loest ein RSA-PKESK-Paket auf und entschluesselt die symmetrisch
 * geschuetzte Nutzlast (SEIPD v2/AEAD ueber
 * {@link HsmSymmetricDecryptorSupport#createAeadDecryptor} - das aeltere,
 * MDC-basierte Profil SEIPD v1 wird von dieser PoC nicht unterstuetzt, siehe
 * {@link #createDataDecryptor(boolean, int, byte[])}).
 * Die private RSA-Operation selbst laeuft ueber {@link HsmRsaEncryptionExecutor}
 * gegen den Schluessel-Handle des Empfaengers.
 */
final class HsmRsaPublicKeyDataDecryptorFactory extends AbstractPublicKeyDataDecryptorFactory {

    private final HsmRsaEncryptionExecutor rsaExecutor;
    private final HsmAesEncryptionExecutor aesExecutor;
    private final HsmKeyHandle recipientKeyHandle;

    HsmRsaPublicKeyDataDecryptorFactory(
            HsmRsaEncryptionExecutor rsaExecutor, HsmAesEncryptionExecutor aesExecutor, HsmKeyHandle recipientKeyHandle) {
        this.rsaExecutor = Objects.requireNonNull(rsaExecutor, "rsaExecutor darf nicht null sein");
        this.aesExecutor = Objects.requireNonNull(aesExecutor, "aesExecutor darf nicht null sein");
        this.recipientKeyHandle = Objects.requireNonNull(recipientKeyHandle, "recipientKeyHandle darf nicht null sein");
    }

    /**
     * {@code recoverSessionData(int, byte[][], int)} ist in {@code PublicKeyDataDecryptorFactory}
     * als {@code @Deprecated} markiert - der als Ersatz vorgeschlagene
     * Zwei-Parameter-Ueberladung ({@code recoverSessionData(PublicKeyEncSessionPacket, InputStreamPacket)})
     * ist in {@code AbstractPublicKeyDataDecryptorFactory} jedoch {@code final}
     * und delegiert selbst intern an genau diese (deprecated) Drei-Parameter-Methode
     * - der einzige verfuegbare Erweiterungspunkt, den auch Bouncy Castles
     * eigene Referenzimplementierung ({@code BcPublicKeyDataDecryptorFactory})
     * ueberschreibt. Die Unterdrueckung ist daher unvermeidbar.
     */
    @Override
    @SuppressWarnings("deprecation")
    public byte[] recoverSessionData(int keyAlgorithm, byte[][] secKeyData, int pkeskVersion) {
        byte[] mpiEncoded = secKeyData[0];
        byte[] ciphertext = Arrays.copyOfRange(mpiEncoded, 2, mpiEncoded.length);
        HsmRsaEncryptionRequest request = HsmRsaEncryption.builder()
                .keyHandle(recipientKeyHandle)
                .operation(HsmCipherOperation.DECRYPT)
                .input(ByteSequence.of(ciphertext))
                .build();
        try {
            return rsaExecutor.execute(request).output().value();
        } catch (RuntimeException e) {
            throw new OpenPgpDecryptionFailedException("Sitzungsschluessel-Wiederherstellung fehlgeschlagen", e);
        }
    }

    @Override
    public PGPDataDecryptor createDataDecryptor(boolean withIntegrityPacket, int encAlgorithm, byte[] key) throws PGPException {
        throw new PGPException(
                "SEIPD v1 (Plain-CFB+MDC) wird von dieser PoC nicht unterstuetzt (siehe "
                        + "Feature-Spezifikation: nur SEIPD v2/AEAD)");
    }

    @Override
    public PGPDataDecryptor createDataDecryptor(AEADEncDataPacket aeadEncDataPacket, PGPSessionKey sessionKey)
            throws PGPException {
        throw new PGPException(
                "Legacy-v5-Style-AEAD (LibrePGP/OCB) ist ausserhalb des Scopes dieser PoC (siehe "
                        + "Feature-Spezifikation: nur SEIPD v2/AEAD)");
    }

    @Override
    public PGPDataDecryptor createDataDecryptor(SymmetricEncIntegrityPacket seipd, PGPSessionKey sessionKey) {
        return HsmSymmetricDecryptorSupport.createAeadDecryptor(aesExecutor, seipd, sessionKey.getKey());
    }
}
