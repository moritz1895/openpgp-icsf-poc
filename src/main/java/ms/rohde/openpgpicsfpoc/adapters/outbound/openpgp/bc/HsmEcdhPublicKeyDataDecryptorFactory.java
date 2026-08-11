package ms.rohde.openpgpicsfpoc.adapters.outbound.openpgp.bc;

import java.util.Arrays;
import java.util.Objects;
import ms.rohde.openpgpicsfpoc.core.domain.PgpEllipticCurve;
import ms.rohde.openpgpicsfpoc.core.domain.PgpKeyReference;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmAesEncryptionExecutor;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmEllipticCurve;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmKeyAgreement;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmKeyAgreementExecutor;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmKeyAgreementRequest;
import org.bouncycastle.bcpg.AEADEncDataPacket;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyEncSessionPacket;
import org.bouncycastle.bcpg.SymmetricEncIntegrityPacket;
import org.bouncycastle.bcpg.X25519PublicBCPGKey;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSessionKey;
import org.bouncycastle.openpgp.operator.AbstractPublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.PGPDataDecryptor;
import org.bouncycastle.openpgp.operator.PGPPad;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;

/**
 * Loest ein ECDH- oder natives X25519-PKESK-Paket auf (Gegenstueck zu
 * {@link HsmEcdhPublicKeyKeyEncryptionMethodGenerator}) und entschluesselt
 * anschliessend die symmetrisch geschuetzte Nutzlast. Die ECDH-Punktmultiplikation
 * mit dem eigenen (im HSM gehaltenen) privaten Schluessel laeuft ueber
 * {@link HsmKeyAgreementExecutor} - die Gegenstelle (der im Paket
 * eingebettete Sender-Punkt) wird ueber {@link EphemeralPeerKeyHandles}
 * adressiert (siehe dortiges JavaDoc zur zugrunde liegenden PoC-Einschraenkung).
 */
final class HsmEcdhPublicKeyDataDecryptorFactory extends AbstractPublicKeyDataDecryptorFactory {

    private final HsmKeyAgreementExecutor keyAgreementExecutor;
    private final HsmAesEncryptionExecutor aesExecutor;
    private final PgpKeyReference recipient;
    private final BcKeyFingerprintCalculator fingerprintCalculator;

    HsmEcdhPublicKeyDataDecryptorFactory(
            HsmKeyAgreementExecutor keyAgreementExecutor,
            HsmAesEncryptionExecutor aesExecutor,
            PgpKeyReference recipient,
            BcKeyFingerprintCalculator fingerprintCalculator) {
        this.keyAgreementExecutor = Objects.requireNonNull(keyAgreementExecutor, "keyAgreementExecutor darf nicht null sein");
        this.aesExecutor = Objects.requireNonNull(aesExecutor, "aesExecutor darf nicht null sein");
        this.recipient = Objects.requireNonNull(recipient, "recipient darf nicht null sein");
        this.fingerprintCalculator = Objects.requireNonNull(fingerprintCalculator, "fingerprintCalculator darf nicht null sein");
    }

    /**
     * Siehe {@link HsmRsaPublicKeyDataDecryptorFactory#recoverSessionData(int, byte[][], int)}
     * zur Begruendung der unvermeidbaren {@code @Deprecated}-Unterdrueckung.
     */
    @Override
    @SuppressWarnings("deprecation")
    public byte[] recoverSessionData(int keyAlgorithm, byte[][] secKeyData, int pkeskVersion) throws PGPException {
        try {
            byte[] enc = secKeyData[0];
            boolean includesSessionKeyAlgorithm = pkeskVersion != PublicKeyEncSessionPacket.VERSION_6;
            if (keyAlgorithm == PublicKeyAlgorithmTags.X25519) {
                return recoverNativeX25519(enc, includesSessionKeyAlgorithm);
            }
            return recoverClassicalEcdh(enc);
        } catch (RuntimeException e) {
            throw new OpenPgpDecryptionFailedException("Sitzungsschluessel-Wiederherstellung fehlgeschlagen", e);
        }
    }

    /**
     * Zerlegt den algorithmus-spezifischen PKESK-Nutzdatenteil fuer natives X25519
     * (RFC 9580 Section 5.1.6): {@code ephemeralPoint(32) || fieldsLength(1) ||
     * [symAlgId(1)] || wrappedSessionKey}. {@code fieldsLength} zaehlt die Bytes ab
     * {@code symAlgId} (falls vorhanden) bis zum Ende - bei einem v6-PKESK
     * ({@code !includesSessionKeyAlgorithm}) entfaellt das {@code symAlgId}-Feld, daher
     * verschieben sich sowohl {@code sessionKeyOffset} als auch die aus
     * {@code fieldsLength} berechnete {@code sessionKeyLength} um je ein Byte.
     */
    private byte[] recoverNativeX25519(byte[] enc, boolean includesSessionKeyAlgorithm) {
        int pointLength = X25519PublicBCPGKey.LENGTH;
        byte[] ephemeralPoint = Arrays.copyOf(enc, pointLength);
        int fieldsLength = enc[pointLength] & 0xff;
        int sessionKeyLength = fieldsLength - (includesSessionKeyAlgorithm ? 1 : 0);
        int sessionKeyOffset = pointLength + 1 + (includesSessionKeyAlgorithm ? 1 : 0);
        byte[] wrappedSessionKey = Arrays.copyOfRange(enc, sessionKeyOffset, sessionKeyOffset + sessionKeyLength);

        byte[] sharedSecret = sharedSecretFor(HsmEllipticCurve.X25519, ephemeralPoint);
        byte[] recipientKeyMaterial = recipient.publicKey().encodedKeyMaterial().value();
        byte[] kek = Rfc6637KeyDerivation.nativeX25519Kdf(ephemeralPoint, recipientKeyMaterial, sharedSecret);
        return new HsmAesKeyWrap(aesExecutor, kek).unwrap(wrappedSessionKey);
    }

    /**
     * Zerlegt den algorithmus-spezifischen PKESK-Nutzdatenteil fuer das klassische
     * ECDH-Fallback-Profil (RFC 6637 Section 8): {@code pointBitLength(2, big-endian) ||
     * ephemeralPoint || fieldsLength(1) || wrappedSessionInfo}. Der Punkt ist - anders als
     * beim nativen X25519-Profil oben - als MPI kodiert, also mit einer fuehrenden
     * Bitlaenge statt fester Byte-Laenge (RFC 6637 traegt beliebige NIST-Kurven, deren
     * Punktlaenge erst zur Laufzeit aus dieser Bitlaenge folgt: {@code (pointBitLength +
     * 7) / 8} rundet dabei auf ganze Bytes auf).
     */
    private byte[] recoverClassicalEcdh(byte[] enc) throws PGPException {
        int pointBitLength = ((enc[0] & 0xff) << 8) + (enc[1] & 0xff);
        int pointLength = (pointBitLength + 7) / 8;
        byte[] ephemeralPoint = Arrays.copyOfRange(enc, 2, 2 + pointLength);

        int fieldsLength = enc[2 + pointLength] & 0xff;
        int keyOffset = 2 + pointLength + 1;
        byte[] wrappedSessionInfo = Arrays.copyOfRange(enc, keyOffset, keyOffset + fieldsLength);

        PgpEllipticCurve curve = recipient.publicKey().curve();
        int[] algorithmPair = PgpKeyMaterialCodec.classicalEcdhAlgorithmPair(curve);
        int hashAlgorithm = algorithmPair[0];
        int symmetricKeyAlgorithm = algorithmPair[1];
        byte[] curveOidEncoded;
        try {
            curveOidEncoded = PgpKeyMaterialCodec.curveOid(curve).getEncoded();
        } catch (java.io.IOException e) {
            throw new PGPException("Kurven-OID-Kodierung fehlgeschlagen: " + e.getMessage(), e);
        }
        byte[] recipientFingerprint =
                PgpKeyMaterialCodec.toPgpPublicKey(recipient.publicKey(), fingerprintCalculator).getFingerprint();

        byte[] sharedSecret = sharedSecretFor(PgpKeyMaterialCodec.toHsmCurve(curve), ephemeralPoint);
        byte[] userKeyingMaterial = Rfc6637KeyDerivation.classicalUserKeyingMaterial(
                curveOidEncoded, hashAlgorithm, symmetricKeyAlgorithm, recipientFingerprint);
        byte[] kek = Rfc6637KeyDerivation.classicalKdf(hashAlgorithm, symmetricKeyAlgorithm, sharedSecret, userKeyingMaterial);
        byte[] paddedSessionInfo = new HsmAesKeyWrap(aesExecutor, kek).unwrap(wrappedSessionInfo);
        return PGPPad.unpadSessionData(paddedSessionInfo);
    }

    private byte[] sharedSecretFor(HsmEllipticCurve curve, byte[] ephemeralPoint) {
        HsmKeyAgreementRequest request = HsmKeyAgreement.builder()
                .curve(curve)
                .localKeyHandle(recipient.keyHandle())
                .peerKeyHandle(EphemeralPeerKeyHandles.deriveFrom(ephemeralPoint))
                .build();
        return keyAgreementExecutor.execute(request).sharedSecret().value();
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
