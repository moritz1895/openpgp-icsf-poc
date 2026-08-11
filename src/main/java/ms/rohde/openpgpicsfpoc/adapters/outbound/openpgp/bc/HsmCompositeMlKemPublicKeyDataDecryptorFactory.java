package ms.rohde.openpgpicsfpoc.adapters.outbound.openpgp.bc;

import java.util.Objects;
import ms.rohde.openpgpicsfpoc.core.domain.ByteSequence;
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
import org.bouncycastle.bcpg.AEADEncDataPacket;
import org.bouncycastle.bcpg.SymmetricEncIntegrityPacket;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSessionKey;
import org.bouncycastle.openpgp.operator.PGPDataDecryptor;
import org.bouncycastle.openpgp.operator.SessionKeyDataDecryptorFactory;

/**
 * Loest ein PKESK-Paket des kompositen ML-KEM-768+X25519-Verfahrens auf (Gegenstueck zu
 * {@link HsmCompositeMlKemKeyEncryptionMethodGenerator}) und stellt anschliessend den
 * Sitzungsschluessel fuer die symmetrische Entschluesselung bereit.
 *
 * <p><b>Warum {@link SessionKeyDataDecryptorFactory} statt
 * {@link org.bouncycastle.openpgp.operator.AbstractPublicKeyDataDecryptorFactory}
 * (wie {@link HsmEcdhPublicKeyDataDecryptorFactory}/{@link HsmRsaPublicKeyDataDecryptorFactory})?</b>
 * Beide Wege fuehren letztlich zu einem BC-{@code PGPEncryptedData}-Objekt, dessen
 * {@code getDataStream(...)} die eigentliche symmetrische Entschluesselung samt
 * Chunk-Verifikation fuer SEIPD v2/AEAD uebernimmt - Logik, die diese Bridge bewusst nicht
 * dupliziert (siehe {@link HsmBackedOpenPgpMessageCodec} fuer die Begruendung, warum
 * dieses Objekt fuer Algorithmus-ID 35 nicht ueber {@code PGPObjectFactory}, sondern nur
 * manuell erzeugt werden kann). Der Sitzungsschluessel wird hier jedoch bereits <b>vor</b>
 * Konstruktion dieses Objekts vollstaendig aufgeloest (ECDH-KEM-Entschluesselung,
 * ML-KEM-Entschluesselung, Schluesselkombinierer, RFC-3394-Unwrap - siehe unten), weil
 * das manuelle Paket-Framing (siehe {@link HsmCompositeMlKemPkeskCodec}) ohnehin bereits
 * alle dafuer noetigen Rohdaten liefert. {@link SessionKeyDataDecryptorFactory} (das
 * BC-Gegenstueck zu {@code gpg --override-session-key}) passt darauf semantisch exakter
 * als das lazy, callback-basierte {@code recoverSessionData(...)} der
 * {@code PublicKeyDataDecryptorFactory}-Familie.</p>
 */
final class HsmCompositeMlKemPublicKeyDataDecryptorFactory implements SessionKeyDataDecryptorFactory {

    private final HsmAesEncryptionExecutor aesExecutor;
    private final PGPSessionKey sessionKey;

    HsmCompositeMlKemPublicKeyDataDecryptorFactory(
            HsmKeyAgreementExecutor keyAgreementExecutor,
            HsmKeyEncapsulationExecutor keyEncapsulationExecutor,
            HsmAesEncryptionExecutor aesExecutor,
            PgpKeyReference recipient,
            HsmCompositeMlKemPkeskCodec.DecodedAlgorithmSpecificData algorithmSpecificData,
            boolean isV3) {
        this.aesExecutor = Objects.requireNonNull(aesExecutor, "aesExecutor darf nicht null sein");
        Objects.requireNonNull(keyAgreementExecutor, "keyAgreementExecutor darf nicht null sein");
        Objects.requireNonNull(keyEncapsulationExecutor, "keyEncapsulationExecutor darf nicht null sein");
        Objects.requireNonNull(recipient, "recipient darf nicht null sein");
        Objects.requireNonNull(algorithmSpecificData, "algorithmSpecificData darf nicht null sein");

        HsmKeyHandle recipientEcdhSubKeyHandle = CompositeMlKemKeyMaterial.ecdhSubKeyHandle(recipient.keyHandle());
        HsmKeyHandle senderEphemeralPeerHandle = EphemeralPeerKeyHandles.deriveFrom(algorithmSpecificData.ecdhCipherText());
        HsmKeyAgreementRequest agreementRequest = HsmKeyAgreement.builder()
                .curve(HsmEllipticCurve.X25519)
                .localKeyHandle(recipientEcdhSubKeyHandle)
                .peerKeyHandle(senderEphemeralPeerHandle)
                .build();
        byte[] ecdhKeyShare = keyAgreementExecutor.execute(agreementRequest).sharedSecret().value();

        HsmKeyEncapsulationRequest encapsulationRequest = HsmKeyEncapsulation.builder()
                .keyHandle(recipient.keyHandle())
                .operation(HsmKeyEncapsulationOperation.DECAPSULATE)
                .encapsulatedKey(ByteSequence.of(algorithmSpecificData.mlkemCipherText()))
                .build();
        byte[] mlkemKeyShare = keyEncapsulationExecutor.execute(encapsulationRequest).sharedSecret().value();

        byte[] recipientEcdhPublicKey =
                CompositeMlKemKeyMaterial.ecdhPublicKeyPart(recipient.publicKey().encodedKeyMaterial().value());
        byte[] kek = HsmCompositeMlKemKeyCombiner.multiKeyCombine(
                mlkemKeyShare,
                ecdhKeyShare,
                algorithmSpecificData.ecdhCipherText(),
                recipientEcdhPublicKey,
                (byte) PgpKeyMaterialCodec.COMPOSITE_ML_KEM_768_X25519_ALGORITHM_TAG);
        byte[] sessionKeyBytes =
                new HsmAesKeyWrap(aesExecutor, kek).unwrap(algorithmSpecificData.wrappedSessionKey());

        int symAlgId = algorithmSpecificData.symAlgId();
        if (isV3) {
            requireSessionKeyLengthMatches(symAlgId, sessionKeyBytes.length);
        } else {
            // v6-PKESK traegt kein eigenes symAlgId-Feld (RFC 9980 Section 4.3.1) - der
            // symmetrische Algorithmus ergibt sich aus dem SEIPD-v2-Paket selbst; das hier
            // gesetzte AES_256 ist ein reiner Platzhalter fuer PGPSessionKey#getAlgorithm(),
            // den createDataDecryptor(SymmetricEncIntegrityPacket, PGPSessionKey) nicht
            // auswertet (siehe Klassen-JavaDoc).
            symAlgId = SymmetricKeyAlgorithmTags.AES_256;
        }
        this.sessionKey = new PGPSessionKey(symAlgId, sessionKeyBytes);
    }

    private static void requireSessionKeyLengthMatches(int symAlgId, int actualLength) {
        int expectedLength = Rfc6637KeyDerivation.keyLength(symAlgId);
        if (actualLength != expectedLength) {
            throw new OpenPgpDecryptionFailedException(
                    "Laenge des entpackten Sitzungsschluessels (" + actualLength
                            + " Byte) passt nicht zur symAlgId " + symAlgId + " (erwartet " + expectedLength
                            + " Byte, RFC 9980 Section 4.3.1)");
        }
    }

    @Override
    public PGPSessionKey getSessionKey() {
        return sessionKey;
    }

    @Override
    public PGPDataDecryptor createDataDecryptor(boolean withIntegrityPacket, int encAlgorithm, byte[] key) throws PGPException {
        throw new PGPException(
                "SEIPD v1 (Plain-CFB+MDC) wird von dieser PoC nicht unterstuetzt (siehe "
                        + "Feature-Spezifikation: nur SEIPD v2/AEAD)");
    }

    @Override
    public PGPDataDecryptor createDataDecryptor(AEADEncDataPacket aeadEncDataPacket, PGPSessionKey ignoredSessionKey)
            throws PGPException {
        throw new PGPException(
                "Legacy-v5-Style-AEAD (LibrePGP/OCB) ist ausserhalb des Scopes dieser PoC (siehe "
                        + "Feature-Spezifikation: nur SEIPD v2/AEAD)");
    }

    @Override
    public PGPDataDecryptor createDataDecryptor(SymmetricEncIntegrityPacket seipd, PGPSessionKey resolvedSessionKey) {
        return HsmSymmetricDecryptorSupport.createAeadDecryptor(aesExecutor, seipd, resolvedSessionKey.getKey());
    }
}
