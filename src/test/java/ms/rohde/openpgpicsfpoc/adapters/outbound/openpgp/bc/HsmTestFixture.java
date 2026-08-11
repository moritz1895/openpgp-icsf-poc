package ms.rohde.openpgpicsfpoc.adapters.outbound.openpgp.bc;

import java.security.KeyPair;
import ms.rohde.openpgpicsfpoc.adapters.outbound.hsm.dummy.DummyHsmAesEncryptionExecutor;
import ms.rohde.openpgpicsfpoc.adapters.outbound.hsm.dummy.DummyHsmKeyAgreementExecutor;
import ms.rohde.openpgpicsfpoc.adapters.outbound.hsm.dummy.DummyHsmKeyEncapsulationExecutor;
import ms.rohde.openpgpicsfpoc.adapters.outbound.hsm.dummy.DummyHsmRsaEncryptionExecutor;
import ms.rohde.openpgpicsfpoc.adapters.outbound.hsm.dummy.DummyHsmSignatureExecutor;
import ms.rohde.openpgpicsfpoc.adapters.outbound.hsm.dummy.InMemoryHsmKeyStore;
import ms.rohde.openpgpicsfpoc.core.domain.ByteSequence;
import ms.rohde.openpgpicsfpoc.core.domain.HsmKeyHandle;
import ms.rohde.openpgpicsfpoc.core.domain.PgpKeyReference;
import ms.rohde.openpgpicsfpoc.core.domain.PgpPublicKey;
import ms.rohde.openpgpicsfpoc.core.domain.PgpPublicKeyAlgorithm;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;

/**
 * Verdrahtet die Dummy-Hsm-Adapter (Test-Doubles fuer den spaeteren
 * ICSF-Adapter, siehe {@code adapters.outbound.hsm.dummy}) zu einer
 * vollstaendigen {@link HsmBackedOpenPgpMessageCodec}-Testumgebung fuer
 * Integrationstests dieser Bridge. Reine Testinfrastruktur - kein
 * Produktivcode.
 */
final class HsmTestFixture {

    final InMemoryHsmKeyStore keyStore = new InMemoryHsmKeyStore();
    final DummyHsmRsaEncryptionExecutor rsaExecutor = new DummyHsmRsaEncryptionExecutor(keyStore);
    final DummyHsmAesEncryptionExecutor aesExecutor = new DummyHsmAesEncryptionExecutor();
    final DummyHsmKeyAgreementExecutor keyAgreementExecutor = new DummyHsmKeyAgreementExecutor(keyStore);
    final DummyHsmKeyEncapsulationExecutor keyEncapsulationExecutor = new DummyHsmKeyEncapsulationExecutor(keyStore);
    final DummyHsmSignatureExecutor signatureExecutor = new DummyHsmSignatureExecutor(keyStore);
    final HsmBackedOpenPgpMessageCodec codec = new HsmBackedOpenPgpMessageCodec(
            rsaExecutor, aesExecutor, keyAgreementExecutor, keyEncapsulationExecutor, signatureExecutor,
            new BcKeyFingerprintCalculator());

    PgpKeyReference registerRecipient(String alias, KeyPair keyPair, PgpPublicKey publicKey) {
        var handle = new HsmKeyHandle(alias);
        keyStore.registerKeyPair(handle, keyPair);
        return new PgpKeyReference(handle, publicKey);
    }

    /**
     * Registriert einen Sender-Schluessel fuer schluesselaustausch-basierte
     * Verschluesselung - sowohl unter seinem eigentlichen Alias (fuer die
     * Verschluesselungsseite, die den Handle direkt aus
     * {@code senderKeyAgreementKey} entnimmt) als auch unter dem
     * inhaltsadressierten Handle, den {@link EphemeralPeerKeyHandles} beim
     * Entschluesseln aus dem im Paket eingebetteten Punkt ableitet (siehe
     * dortiges JavaDoc zur zugrunde liegenden PoC-Einschraenkung).
     */
    PgpKeyReference registerSenderKeyAgreementKey(String alias, KeyPair keyPair, PgpPublicKey publicKey) {
        var reference = registerRecipient(alias, keyPair, publicKey);
        var derivedHandle = EphemeralPeerKeyHandles.deriveFrom(publicKey.encodedKeyMaterial().value());
        keyStore.registerPublicKey(derivedHandle, keyPair.getPublic());
        return reference;
    }

    /**
     * Registriert einen ML-KEM-768+X25519-Komposit-Empfaenger: das ML-KEM-Teilschluesselpaar
     * unter {@code alias} (dem primaeren Handle der zurueckgegebenen
     * {@code PgpKeyReference}), das X25519-Teilschluesselpaar unter dem davon abgeleiteten
     * Handle (siehe {@link CompositeMlKemKeyMaterial#ecdhSubKeyHandle(HsmKeyHandle)}) - die
     * fuer diese Bridge festgelegte Zwei-Handle-Konvention fuer Komposit-Empfaenger (siehe
     * dortiges JavaDoc).
     */
    PgpKeyReference registerCompositeMlKemRecipient(
            String alias, KeyPair ecdhKeyPair, KeyPair mlkemKeyPair, byte[] ecdhPublicKeyBytes, byte[] mlkemPublicKeyBytes) {
        var handle = new HsmKeyHandle(alias);
        keyStore.registerKeyPair(handle, mlkemKeyPair);
        keyStore.registerKeyPair(CompositeMlKemKeyMaterial.ecdhSubKeyHandle(handle), ecdhKeyPair);
        var publicKey = new PgpPublicKey(
                PgpPublicKeyAlgorithm.ML_KEM_768_X25519,
                ByteSequence.of(CompositeMlKemKeyMaterial.compose(ecdhPublicKeyBytes, mlkemPublicKeyBytes)));
        return new PgpKeyReference(handle, publicKey);
    }
}
