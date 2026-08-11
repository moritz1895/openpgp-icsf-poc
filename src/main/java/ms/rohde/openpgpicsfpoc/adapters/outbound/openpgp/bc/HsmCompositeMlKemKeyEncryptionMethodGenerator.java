package ms.rohde.openpgpicsfpoc.adapters.outbound.openpgp.bc;

import java.util.Objects;
import ms.rohde.openpgpicsfpoc.core.domain.HsmKeyHandle;
import ms.rohde.openpgpicsfpoc.core.domain.PgpKeyReference;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmAesEncryptionExecutor;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmEllipticCurve;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmKeyAgreement;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmKeyAgreementExecutor;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmKeyAgreementRequest;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmKeyEncapsulation;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmKeyEncapsulationExecutor;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmKeyEncapsulationOperation;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmKeyEncapsulationRequest;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmKeyEncapsulationResult;
import org.bouncycastle.bcpg.ContainedPacket;
import org.bouncycastle.bcpg.PublicKeyEncSessionPacket;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.operator.PGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.PGPKeyEncryptionMethodGenerator;

/**
 * Erzeugt das PKESK-Paket fuer das komposite ML-KEM-768+X25519-Verfahren (RFC 9980,
 * Algorithmus-ID 35) - Vorbild ist {@link HsmEcdhPublicKeyKeyEncryptionMethodGenerator}
 * fuer das native X25519-Profil, dessen Sender-Schluessel-Vereinfachung (statischer statt
 * je Nachricht neu erzeugter ephemerer Sender-Schluessel) hier fuer die ECDH-Haelfte
 * identisch uebernommen wird.
 *
 * <p><b>Warum nicht {@link org.bouncycastle.openpgp.operator.PublicKeyKeyEncryptionMethodGenerator}
 * erweitern (wie alle anderen Generatoren dieser Bridge)?</b> Dessen Konstruktor sowie
 * {@code encodeEncryptedSessionInfo(byte[])} pruefen den Algorithmus-Tag des
 * {@link PGPPublicKey} gegen eine feste, in {@code bcpg-jdk18on} 1.85 einprogrammierte
 * Liste bekannter Algorithmen (RSA, ElGamal, ECDH, X25519/X448, ...) - Algorithmus-ID 35
 * ist darin nicht enthalten, beide Stellen wuerden mit einer
 * {@code IllegalArgumentException} bzw. {@code PGPException} abbrechen. Diese Klasse
 * implementiert daher direkt das schlanke {@link PGPKeyEncryptionMethodGenerator}-Interface
 * (nur die Methode {@link #generate(PGPDataEncryptorBuilder, byte[])}), das
 * {@link org.bouncycastle.openpgp.PGPEncryptedDataGenerator#addMethod(PGPKeyEncryptionMethodGenerator)}
 * unveraendert entgegennimmt, und baut das resultierende
 * {@link PublicKeyEncSessionPacket} ueber dessen <b>oeffentliche</b> Kodierungs-Fabrikmethoden
 * {@code createV3PKESKPacket}/{@code createV6PKESKPacket} zusammen - diese sind, anders
 * als der lesende (parsende) Konstruktor, nicht auf einen bekannten Algorithmus-Tag
 * beschraenkt.</p>
 *
 * <p>Orchestrierung je Aufruf: ECDH-KEM-Verschluesselung (Section 4.1.1.1) ueber
 * {@link HsmKeyAgreementExecutor} (Sender-Schluessel-Handle x abgeleiteter
 * ECDH-Teilschluessel-Handle des Empfaengers, siehe {@link CompositeMlKemKeyMaterial}),
 * ML-KEM-Verschluesselung (Section 4.1.2) ueber {@link HsmKeyEncapsulationExecutor}
 * (Empfaenger-Handle), Schluesselkombinierer ({@link HsmCompositeMlKemKeyCombiner}),
 * RFC-3394-Schluesselverpackung ({@link HsmAesKeyWrap}) und PKESK-Byte-Layout
 * ({@link HsmCompositeMlKemPkeskCodec}).</p>
 */
final class HsmCompositeMlKemKeyEncryptionMethodGenerator implements PGPKeyEncryptionMethodGenerator {

    private final PGPPublicKey recipientPgpPublicKey;
    private final HsmKeyAgreementExecutor keyAgreementExecutor;
    private final HsmKeyEncapsulationExecutor keyEncapsulationExecutor;
    private final HsmAesEncryptionExecutor aesExecutor;
    private final PgpKeyReference recipient;
    private final PgpKeyReference senderKeyAgreementKey;

    HsmCompositeMlKemKeyEncryptionMethodGenerator(
            PGPPublicKey recipientPgpPublicKey,
            HsmKeyAgreementExecutor keyAgreementExecutor,
            HsmKeyEncapsulationExecutor keyEncapsulationExecutor,
            HsmAesEncryptionExecutor aesExecutor,
            PgpKeyReference recipient,
            PgpKeyReference senderKeyAgreementKey) {
        this.recipientPgpPublicKey =
                Objects.requireNonNull(recipientPgpPublicKey, "recipientPgpPublicKey darf nicht null sein");
        this.keyAgreementExecutor = Objects.requireNonNull(keyAgreementExecutor, "keyAgreementExecutor darf nicht null sein");
        this.keyEncapsulationExecutor =
                Objects.requireNonNull(keyEncapsulationExecutor, "keyEncapsulationExecutor darf nicht null sein");
        this.aesExecutor = Objects.requireNonNull(aesExecutor, "aesExecutor darf nicht null sein");
        this.recipient = Objects.requireNonNull(recipient, "recipient darf nicht null sein");
        this.senderKeyAgreementKey =
                Objects.requireNonNull(senderKeyAgreementKey, "senderKeyAgreementKey darf nicht null sein");
    }

    @Override
    public ContainedPacket generate(PGPDataEncryptorBuilder dataEncryptorBuilder, byte[] sessionKey) throws PGPException {
        boolean useV6Pkesk = dataEncryptorBuilder.getAeadAlgorithm() > 0 && !dataEncryptorBuilder.isV5StyleAEAD();
        boolean isV3 = !useV6Pkesk;
        int symAlgId = dataEncryptorBuilder.getAlgorithm();

        byte[] recipientCompositeMaterial = recipient.publicKey().encodedKeyMaterial().value();
        byte[] recipientEcdhPublicKey = CompositeMlKemKeyMaterial.ecdhPublicKeyPart(recipientCompositeMaterial);
        HsmKeyHandle recipientEcdhSubKeyHandle = CompositeMlKemKeyMaterial.ecdhSubKeyHandle(recipient.keyHandle());

        HsmKeyAgreementRequest agreementRequest = HsmKeyAgreement.builder()
                .curve(HsmEllipticCurve.X25519)
                .localKeyHandle(senderKeyAgreementKey.keyHandle())
                .peerKeyHandle(recipientEcdhSubKeyHandle)
                .build();
        byte[] ecdhKeyShare = keyAgreementExecutor.execute(agreementRequest).sharedSecret().value();
        byte[] ecdhCipherText = senderKeyAgreementKey.publicKey().encodedKeyMaterial().value();

        HsmKeyEncapsulationRequest encapsulationRequest = HsmKeyEncapsulation.builder()
                .keyHandle(recipient.keyHandle())
                .operation(HsmKeyEncapsulationOperation.ENCAPSULATE)
                .build();
        HsmKeyEncapsulationResult encapsulationResult = keyEncapsulationExecutor.execute(encapsulationRequest);
        byte[] mlkemKeyShare = encapsulationResult.sharedSecret().value();
        byte[] mlkemCipherText = Objects.requireNonNull(
                        encapsulationResult.encapsulatedKey(), "ENCAPSULATE muss ein Chiffrat liefern")
                .value();

        byte[] kek = HsmCompositeMlKemKeyCombiner.multiKeyCombine(
                mlkemKeyShare,
                ecdhKeyShare,
                ecdhCipherText,
                recipientEcdhPublicKey,
                (byte) PgpKeyMaterialCodec.COMPOSITE_ML_KEM_768_X25519_ALGORITHM_TAG);
        byte[] wrappedSessionKey = new HsmAesKeyWrap(aesExecutor, kek).wrap(sessionKey);

        byte[] algorithmSpecificData = HsmCompositeMlKemPkeskCodec.encodeAlgorithmSpecificData(
                ecdhCipherText, mlkemCipherText, wrappedSessionKey, isV3, symAlgId);
        byte[][] data = {algorithmSpecificData};

        if (isV3) {
            return PublicKeyEncSessionPacket.createV3PKESKPacket(
                    recipientPgpPublicKey.getKeyID(),
                    PgpKeyMaterialCodec.COMPOSITE_ML_KEM_768_X25519_ALGORITHM_TAG,
                    data);
        }
        return PublicKeyEncSessionPacket.createV6PKESKPacket(
                recipientPgpPublicKey.getVersion(),
                recipientPgpPublicKey.getFingerprint(),
                PgpKeyMaterialCodec.COMPOSITE_ML_KEM_768_X25519_ALGORITHM_TAG,
                data);
    }
}
