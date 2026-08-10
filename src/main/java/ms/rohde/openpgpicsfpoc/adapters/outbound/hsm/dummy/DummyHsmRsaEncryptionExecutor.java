package ms.rohde.openpgpicsfpoc.adapters.outbound.hsm.dummy;

import jakarta.inject.Inject;
import java.security.GeneralSecurityException;
import java.util.Objects;
import javax.crypto.Cipher;
import ms.rohde.hexagonalarch.annotations.InfrastructureServiceAdapter;
import ms.rohde.openpgpicsfpoc.core.domain.ByteSequence;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmCipherOperation;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmRsaEncryptionExecutor;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmRsaEncryptionRequest;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmRsaEncryptionResult;

/**
 * <b>Kein Produktivcode - reines Testdouble fuer den spaeteren ICSF-Adapter.</b>
 *
 * <p>Funktionale Nachbildung von {@link HsmRsaEncryptionExecutor} auf Basis
 * von Standard-JDK-Crypto ({@code javax.crypto.Cipher} mit
 * {@code RSA/ECB/PKCS1Padding}). Schluesselmaterial kommt ausschliesslich aus
 * dem {@link InMemoryHsmKeyStore}.</p>
 */
@InfrastructureServiceAdapter
public final class DummyHsmRsaEncryptionExecutor implements HsmRsaEncryptionExecutor {

    private static final String TRANSFORMATION = "RSA/ECB/PKCS1Padding";

    private final InMemoryHsmKeyStore keyStore;

    @Inject
    public DummyHsmRsaEncryptionExecutor(InMemoryHsmKeyStore keyStore) {
        this.keyStore = Objects.requireNonNull(keyStore, "keyStore darf nicht null sein");
    }

    @Override
    public HsmRsaEncryptionResult execute(HsmRsaEncryptionRequest request) {
        Objects.requireNonNull(request, "request darf nicht null sein");
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            if (request.operation() == HsmCipherOperation.ENCRYPT) {
                cipher.init(Cipher.ENCRYPT_MODE, keyStore.requirePublicKey(request.keyHandle()));
            } else {
                cipher.init(Cipher.DECRYPT_MODE, keyStore.requirePrivateKey(request.keyHandle()));
            }
            return new HsmRsaEncryptionResult(ByteSequence.of(cipher.doFinal(request.input().value())));
        } catch (GeneralSecurityException e) {
            throw new HsmDummyOperationException("RSA-Operation fehlgeschlagen", e);
        }
    }
}
