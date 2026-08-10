package ms.rohde.openpgpicsfpoc.ports.outbound.hsm;

import java.util.Objects;
import ms.rohde.openpgpicsfpoc.core.domain.HsmKeyHandle;
import org.jspecify.annotations.Nullable;

/**
 * Fluenter Builder fuer eine {@link HsmKeyAgreementRequest}.
 *
 * <p>Reine Zusammenbau-Logik ohne Infrastruktur-Abhaengigkeit - siehe
 * JavaDoc auf {@link HsmRsaEncryption} fuer die Rollentrennung
 * Builder/Executor.</p>
 */
public interface HsmKeyAgreement {

    HsmKeyAgreement curve(HsmEllipticCurve curve);

    HsmKeyAgreement localKeyHandle(HsmKeyHandle localKeyHandle);

    HsmKeyAgreement peerKeyHandle(HsmKeyHandle peerKeyHandle);

    HsmKeyAgreementRequest build();

    static HsmKeyAgreement builder() {
        return new Default();
    }

    final class Default implements HsmKeyAgreement {

        private @Nullable HsmEllipticCurve curve;
        private @Nullable HsmKeyHandle localKeyHandle;
        private @Nullable HsmKeyHandle peerKeyHandle;

        private Default() {}

        @Override
        public HsmKeyAgreement curve(HsmEllipticCurve curve) {
            this.curve = Objects.requireNonNull(curve, "curve darf nicht null sein");
            return this;
        }

        @Override
        public HsmKeyAgreement localKeyHandle(HsmKeyHandle localKeyHandle) {
            this.localKeyHandle = Objects.requireNonNull(localKeyHandle, "localKeyHandle darf nicht null sein");
            return this;
        }

        @Override
        public HsmKeyAgreement peerKeyHandle(HsmKeyHandle peerKeyHandle) {
            this.peerKeyHandle = Objects.requireNonNull(peerKeyHandle, "peerKeyHandle darf nicht null sein");
            return this;
        }

        @Override
        public HsmKeyAgreementRequest build() {
            if (curve == null) {
                throw new IllegalStateException("curve muss gesetzt sein");
            }
            if (localKeyHandle == null) {
                throw new IllegalStateException("localKeyHandle muss gesetzt sein");
            }
            if (peerKeyHandle == null) {
                throw new IllegalStateException("peerKeyHandle muss gesetzt sein");
            }
            return new HsmKeyAgreementRequest(curve, localKeyHandle, peerKeyHandle);
        }
    }
}
