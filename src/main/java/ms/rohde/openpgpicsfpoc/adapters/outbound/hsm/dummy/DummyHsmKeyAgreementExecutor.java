package ms.rohde.openpgpicsfpoc.adapters.outbound.hsm.dummy;

import jakarta.inject.Inject;
import java.security.GeneralSecurityException;
import java.util.Objects;
import javax.crypto.KeyAgreement;
import ms.rohde.hexagonalarch.annotations.InfrastructureServiceAdapter;
import ms.rohde.openpgpicsfpoc.core.domain.ByteSequence;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmEllipticCurve;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmKeyAgreementExecutor;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmKeyAgreementRequest;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmKeyAgreementResult;

/**
 * <b>Kein Produktivcode - reines Testdouble fuer den spaeteren ICSF-Adapter.</b>
 *
 * <p>Funktionale Nachbildung von {@link HsmKeyAgreementExecutor} auf Basis
 * von Standard-JDK-Crypto ({@code javax.crypto.KeyAgreement} mit den seit
 * JDK 11 nativen X25519- bzw. den klassischen ECDH-Algorithmen).</p>
 */
@InfrastructureServiceAdapter
public final class DummyHsmKeyAgreementExecutor implements HsmKeyAgreementExecutor {

    private final InMemoryHsmKeyStore keyStore;

    @Inject
    public DummyHsmKeyAgreementExecutor(InMemoryHsmKeyStore keyStore) {
        this.keyStore = Objects.requireNonNull(keyStore, "keyStore darf nicht null sein");
    }

    @Override
    public HsmKeyAgreementResult execute(HsmKeyAgreementRequest request) {
        Objects.requireNonNull(request, "request darf nicht null sein");
        try {
            KeyAgreement keyAgreement = KeyAgreement.getInstance(jcaAlgorithmName(request.curve()));
            keyAgreement.init(keyStore.requirePrivateKey(request.localKeyHandle()));
            keyAgreement.doPhase(keyStore.requirePublicKey(request.peerKeyHandle()), true);
            return new HsmKeyAgreementResult(ByteSequence.of(keyAgreement.generateSecret()));
        } catch (GeneralSecurityException e) {
            throw new HsmDummyOperationException("Schluesselaustausch fehlgeschlagen", e);
        }
    }

    private static String jcaAlgorithmName(HsmEllipticCurve curve) {
        return curve == HsmEllipticCurve.X25519 ? "X25519" : "ECDH";
    }
}
