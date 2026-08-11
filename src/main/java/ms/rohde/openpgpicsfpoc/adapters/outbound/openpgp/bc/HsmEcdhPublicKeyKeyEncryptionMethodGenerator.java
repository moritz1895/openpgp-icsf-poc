package ms.rohde.openpgpicsfpoc.adapters.outbound.openpgp.bc;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Objects;
import ms.rohde.openpgpicsfpoc.core.domain.PgpKeyReference;
import ms.rohde.openpgpicsfpoc.core.domain.PgpPublicKeyAlgorithm;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmAesEncryptionExecutor;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmEllipticCurve;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmKeyAgreement;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmKeyAgreementExecutor;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmKeyAgreementRequest;
import org.bouncycastle.bcpg.ECDHPublicBCPGKey;
import org.bouncycastle.bcpg.MPInteger;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.operator.PGPPad;
import org.bouncycastle.openpgp.operator.PublicKeyKeyEncryptionMethodGenerator;

/**
 * Erzeugt das PKESK-Paket fuer schluesselaustausch-basierte Empfaenger -
 * sowohl das native X25519-Profil (RFC 9580) als auch das klassische
 * ECDH-Fallback-Profil ueber NIST-Kurven (RFC 6637). Die
 * ECDH-Punktmultiplikation laeuft ueber {@link HsmKeyAgreementExecutor}
 * (Sender-Schluessel-Handle x Empfaenger-Schluessel-Handle); die
 * anschliessende Schluesselableitung (RFC-6637-KDF bzw. RFC-9580-HKDF) und
 * die RFC-3394-Schluesselverpackung sind lokale, unkritische Schritte (siehe
 * {@link Rfc6637KeyDerivation}, {@link HsmAesKeyWrap}).
 *
 * <p>Der in {@code senderKeyAgreementKey} referenzierte Schluessel ist laut
 * {@code EncryptOpenPgpMessageCommand} ein vorab im HSM vorhandener,
 * statischer Schluessel statt eines je Nachricht neu erzeugten ephemeren
 * Schluessels (dokumentierte PoC-Vereinfachung) - dessen oeffentlicher Teil
 * wird an der Stelle des "ephemeren" Punkts in das PKESK-Paket eingebettet.</p>
 */
final class HsmEcdhPublicKeyKeyEncryptionMethodGenerator extends PublicKeyKeyEncryptionMethodGenerator {

    private final HsmKeyAgreementExecutor keyAgreementExecutor;
    private final HsmAesEncryptionExecutor aesExecutor;
    private final PgpKeyReference recipient;
    private final PgpKeyReference senderKeyAgreementKey;

    HsmEcdhPublicKeyKeyEncryptionMethodGenerator(
            PGPPublicKey recipientPgpPublicKey,
            HsmKeyAgreementExecutor keyAgreementExecutor,
            HsmAesEncryptionExecutor aesExecutor,
            PgpKeyReference recipient,
            PgpKeyReference senderKeyAgreementKey) {
        super(recipientPgpPublicKey);
        this.keyAgreementExecutor = Objects.requireNonNull(keyAgreementExecutor, "keyAgreementExecutor darf nicht null sein");
        this.aesExecutor = Objects.requireNonNull(aesExecutor, "aesExecutor darf nicht null sein");
        this.recipient = Objects.requireNonNull(recipient, "recipient darf nicht null sein");
        this.senderKeyAgreementKey =
                Objects.requireNonNull(senderKeyAgreementKey, "senderKeyAgreementKey darf nicht null sein");
    }

    @Override
    protected byte[] encryptSessionInfo(PGPPublicKey pubKey, byte[] sessionKey, byte symAlgId, boolean isV3)
            throws PGPException {
        PgpPublicKeyAlgorithm algorithm = recipient.publicKey().algorithm();
        HsmEllipticCurve curve = algorithm == PgpPublicKeyAlgorithm.X25519
                ? HsmEllipticCurve.X25519
                : PgpKeyMaterialCodec.toHsmCurve(recipient.publicKey().curve());

        HsmKeyAgreementRequest sharedSecretRequest = HsmKeyAgreement.builder()
                .curve(curve)
                .localKeyHandle(senderKeyAgreementKey.keyHandle())
                .peerKeyHandle(recipient.keyHandle())
                .build();
        byte[] sharedSecret = keyAgreementExecutor.execute(sharedSecretRequest).sharedSecret().value();
        byte[] senderPublicKeyMaterial = senderKeyAgreementKey.publicKey().encodedKeyMaterial().value();

        if (algorithm == PgpPublicKeyAlgorithm.X25519) {
            return encryptForNativeX25519(pubKey, sessionKey, symAlgId, isV3, sharedSecret, senderPublicKeyMaterial);
        }
        return encryptForClassicalEcdh(pubKey, sessionKey, symAlgId, isV3, sharedSecret, senderPublicKeyMaterial);
    }

    private byte[] encryptForNativeX25519(
            PGPPublicKey pubKey, byte[] sessionKey, byte symAlgId, boolean isV3, byte[] sharedSecret,
            byte[] senderPublicKeyMaterial) {
        byte[] recipientKeyMaterial = pubKey.getPublicKeyPacket().getKey().getEncoded();
        byte[] kek = Rfc6637KeyDerivation.nativeX25519Kdf(senderPublicKeyMaterial, recipientKeyMaterial, sharedSecret);
        byte[] wrapped = new HsmAesKeyWrap(aesExecutor, kek).wrap(sessionKey);
        return getSessionInfo(senderPublicKeyMaterial, isV3 ? symAlgId : (byte) 0, wrapped);
    }

    private byte[] encryptForClassicalEcdh(
            PGPPublicKey pubKey, byte[] sessionKey, byte symAlgId, boolean isV3, byte[] sharedSecret,
            byte[] senderPublicKeyMaterial)
            throws PGPException {
        ECDHPublicBCPGKey ecKey = (ECDHPublicBCPGKey) pubKey.getPublicKeyPacket().getKey();
        try {
            byte[] userKeyingMaterial = Rfc6637KeyDerivation.classicalUserKeyingMaterial(
                    ecKey.getCurveOID().getEncoded(), ecKey.getHashAlgorithm(), ecKey.getSymmetricKeyAlgorithm(),
                    pubKey.getFingerprint());
            byte[] sessionInfo = createSessionInfo(isV3 ? symAlgId : (byte) 0, sessionKey);
            byte[] padded = PGPPad.padSessionData(sessionInfo);
            byte[] kek = Rfc6637KeyDerivation.classicalKdf(
                    ecKey.getHashAlgorithm(), ecKey.getSymmetricKeyAlgorithm(), sharedSecret, userKeyingMaterial);
            byte[] wrapped = new HsmAesKeyWrap(aesExecutor, kek).wrap(padded);
            byte[] ephemeralPointMpi = new MPInteger(new BigInteger(1, senderPublicKeyMaterial)).getEncoded();
            return getSessionInfo(ephemeralPointMpi, (byte) 0, wrapped);
        } catch (IOException e) {
            throw new PGPException("Paket-Kodierung fehlgeschlagen: " + e.getMessage(), e);
        }
    }
}
