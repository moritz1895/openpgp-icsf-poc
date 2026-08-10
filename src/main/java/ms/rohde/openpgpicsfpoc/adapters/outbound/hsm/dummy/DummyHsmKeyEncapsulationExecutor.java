package ms.rohde.openpgpicsfpoc.adapters.outbound.hsm.dummy;

import jakarta.inject.Inject;
import java.security.GeneralSecurityException;
import java.util.Objects;
import javax.crypto.KEM;
import ms.rohde.hexagonalarch.annotations.InfrastructureServiceAdapter;
import ms.rohde.openpgpicsfpoc.core.domain.ByteSequence;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmKeyEncapsulationExecutor;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmKeyEncapsulationRequest;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmKeyEncapsulationResult;

/**
 * <b>Kein Produktivcode - reines Testdouble fuer den spaeteren ICSF-Adapter.</b>
 *
 * <p>Funktionale Nachbildung von {@link HsmKeyEncapsulationExecutor} auf
 * Basis der seit Java 24 (JEP 496) nativ verfuegbaren ML-KEM-Unterstuetzung
 * ueber {@code javax.crypto.KEM}. Eine zusaetzliche Bouncy-Castle-
 * Abhaengigkeit war dafuer nicht erforderlich.</p>
 */
@InfrastructureServiceAdapter
public final class DummyHsmKeyEncapsulationExecutor implements HsmKeyEncapsulationExecutor {

    private static final String ALGORITHM = "ML-KEM-768";

    private final InMemoryHsmKeyStore keyStore;

    @Inject
    public DummyHsmKeyEncapsulationExecutor(InMemoryHsmKeyStore keyStore) {
        this.keyStore = Objects.requireNonNull(keyStore, "keyStore darf nicht null sein");
    }

    @Override
    public HsmKeyEncapsulationResult execute(HsmKeyEncapsulationRequest request) {
        Objects.requireNonNull(request, "request darf nicht null sein");
        try {
            KEM kem = KEM.getInstance(ALGORITHM);
            return switch (request.operation()) {
                case ENCAPSULATE -> encapsulate(kem, request);
                case DECAPSULATE -> decapsulate(kem, request);
            };
        } catch (GeneralSecurityException e) {
            throw new HsmDummyOperationException("Schluesselkapselung fehlgeschlagen", e);
        }
    }

    private HsmKeyEncapsulationResult encapsulate(KEM kem, HsmKeyEncapsulationRequest request)
            throws GeneralSecurityException {
        KEM.Encapsulator encapsulator = kem.newEncapsulator(keyStore.requirePublicKey(request.keyHandle()));
        KEM.Encapsulated encapsulated = encapsulator.encapsulate();
        return new HsmKeyEncapsulationResult(
                ByteSequence.of(encapsulated.key().getEncoded()), ByteSequence.of(encapsulated.encapsulation()));
    }

    private HsmKeyEncapsulationResult decapsulate(KEM kem, HsmKeyEncapsulationRequest request)
            throws GeneralSecurityException {
        KEM.Decapsulator decapsulator = kem.newDecapsulator(keyStore.requirePrivateKey(request.keyHandle()));
        var encapsulatedKey =
                Objects.requireNonNull(request.encapsulatedKey(), "encapsulatedKey fehlt fuer DECAPSULATE");
        var sharedSecret = decapsulator.decapsulate(encapsulatedKey.value());
        return new HsmKeyEncapsulationResult(ByteSequence.of(sharedSecret.getEncoded()), null);
    }
}
