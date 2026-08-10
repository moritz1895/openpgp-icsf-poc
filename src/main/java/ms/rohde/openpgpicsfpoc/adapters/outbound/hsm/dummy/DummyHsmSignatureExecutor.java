package ms.rohde.openpgpicsfpoc.adapters.outbound.hsm.dummy;

import jakarta.inject.Inject;
import java.security.GeneralSecurityException;
import java.security.Signature;
import java.util.Objects;
import ms.rohde.hexagonalarch.annotations.InfrastructureServiceAdapter;
import ms.rohde.openpgpicsfpoc.core.domain.ByteSequence;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmSignatureAlgorithm;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmSignatureExecutor;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmSignatureRequest;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmSignatureResult;

/**
 * <b>Kein Produktivcode - reines Testdouble fuer den spaeteren ICSF-Adapter.</b>
 *
 * <p>Funktionale Nachbildung von {@link HsmSignatureExecutor} auf Basis von
 * Standard-JDK-Crypto. {@code NONEwithRSA}/{@code NONEwithECDSA} signieren
 * den bereits berechneten Digest direkt (kein erneutes Hashing); fuer
 * {@code EDDSA} und {@code ML_DSA_65_ED25519} wird der Digest als
 * Roheingabe an die jeweilige nativ in Java 25 verfuegbare Signatur
 * (Ed25519 bzw. ML-DSA-65, siehe JEP 497) uebergeben - siehe JavaDoc auf
 * {@link HsmSignatureRequest} zur Abweichung vom "pure EdDSA"-Schema.</p>
 *
 * <p><b>Vereinfachung fuer {@code ML_DSA_65_ED25519}:</b> diese PoC bildet
 * im Dummy-Adapter nur die ML-DSA-65-Kernkomponente der kompositen RFC-9980-
 * Signatur (Alg-ID 30) ab. Die zusaetzliche Ed25519-Komponente sowie die
 * komposite Kodierung beider Signaturanteile ist Sache der spaeteren
 * OpenPGP-Paket-Kodierung (Bouncy-Castle-Bridge).</p>
 */
@InfrastructureServiceAdapter
public final class DummyHsmSignatureExecutor implements HsmSignatureExecutor {

    private final InMemoryHsmKeyStore keyStore;

    @Inject
    public DummyHsmSignatureExecutor(InMemoryHsmKeyStore keyStore) {
        this.keyStore = Objects.requireNonNull(keyStore, "keyStore darf nicht null sein");
    }

    @Override
    public HsmSignatureResult execute(HsmSignatureRequest request) {
        Objects.requireNonNull(request, "request darf nicht null sein");
        try {
            Signature signature = Signature.getInstance(jcaAlgorithmName(request.algorithm()));
            signature.initSign(keyStore.requirePrivateKey(request.keyHandle()));
            signature.update(request.digest().value());
            return new HsmSignatureResult(ByteSequence.of(signature.sign()));
        } catch (GeneralSecurityException e) {
            throw new HsmDummyOperationException("Signaturoperation fehlgeschlagen", e);
        }
    }

    private static String jcaAlgorithmName(HsmSignatureAlgorithm algorithm) {
        return switch (algorithm) {
            case RSA_PKCS1V15 -> "NONEwithRSA";
            case ECDSA -> "NONEwithECDSA";
            case EDDSA -> "Ed25519";
            case ML_DSA_65_ED25519 -> "ML-DSA-65";
        };
    }
}
