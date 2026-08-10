package ms.rohde.openpgpicsfpoc.adapters.outbound.openpgp.bc;

import java.security.KeyPair;
import ms.rohde.openpgpicsfpoc.adapters.outbound.hsm.dummy.DummyHsmAesEncryptionExecutor;
import ms.rohde.openpgpicsfpoc.adapters.outbound.hsm.dummy.DummyHsmKeyAgreementExecutor;
import ms.rohde.openpgpicsfpoc.adapters.outbound.hsm.dummy.DummyHsmRsaEncryptionExecutor;
import ms.rohde.openpgpicsfpoc.adapters.outbound.hsm.dummy.DummyHsmSignatureExecutor;
import ms.rohde.openpgpicsfpoc.adapters.outbound.hsm.dummy.InMemoryHsmKeyStore;
import ms.rohde.openpgpicsfpoc.core.domain.HsmKeyHandle;
import ms.rohde.openpgpicsfpoc.core.domain.PgpKeyReference;
import ms.rohde.openpgpicsfpoc.core.domain.PgpPublicKey;

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
    final DummyHsmSignatureExecutor signatureExecutor = new DummyHsmSignatureExecutor(keyStore);
    final HsmBackedOpenPgpMessageCodec codec =
            new HsmBackedOpenPgpMessageCodec(rsaExecutor, aesExecutor, keyAgreementExecutor, signatureExecutor);

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
}
