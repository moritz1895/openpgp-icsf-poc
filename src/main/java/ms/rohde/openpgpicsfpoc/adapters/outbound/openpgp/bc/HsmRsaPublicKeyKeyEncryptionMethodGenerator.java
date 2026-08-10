package ms.rohde.openpgpicsfpoc.adapters.outbound.openpgp.bc;

import java.util.Objects;
import ms.rohde.openpgpicsfpoc.core.domain.ByteSequence;
import ms.rohde.openpgpicsfpoc.core.domain.HsmKeyHandle;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmCipherOperation;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmRsaEncryption;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmRsaEncryptionExecutor;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.operator.PublicKeyKeyEncryptionMethodGenerator;

/**
 * Erzeugt das PKESK-Paket (Public-Key Encrypted Session Key) fuer
 * RSA-Empfaenger: das Paket-Framing (Sitzungsinfo-Aufbau, Pruefsumme,
 * MPI-Kodierung, PKESK-Versionierung) uebernimmt vollstaendig die
 * Bouncy-Castle-Basisklasse {@link PublicKeyKeyEncryptionMethodGenerator};
 * diese Klasse liefert ausschliesslich die eigentliche RSA-PKCS#1v1.5-Operation,
 * ausgefuehrt ueber {@link HsmRsaEncryptionExecutor} gegen den Empfaenger-Schluessel-Handle.
 */
final class HsmRsaPublicKeyKeyEncryptionMethodGenerator extends PublicKeyKeyEncryptionMethodGenerator {

    private final HsmRsaEncryptionExecutor executor;
    private final HsmKeyHandle recipientKeyHandle;

    HsmRsaPublicKeyKeyEncryptionMethodGenerator(
            PGPPublicKey recipientPublicKey, HsmRsaEncryptionExecutor executor, HsmKeyHandle recipientKeyHandle) {
        super(recipientPublicKey);
        this.executor = Objects.requireNonNull(executor, "executor darf nicht null sein");
        this.recipientKeyHandle = Objects.requireNonNull(recipientKeyHandle, "recipientKeyHandle darf nicht null sein");
    }

    @Override
    protected byte[] encryptSessionInfo(PGPPublicKey pubKey, byte[] sessionKey, byte symAlgId, boolean isV3)
            throws PGPException {
        byte[] sessionInfo = createSessionInfo(isV3 ? symAlgId : (byte) 0, sessionKey);
        var request = HsmRsaEncryption.builder()
                .keyHandle(recipientKeyHandle)
                .operation(HsmCipherOperation.ENCRYPT)
                .input(ByteSequence.of(sessionInfo))
                .build();
        return executor.execute(request).output().value();
    }
}
