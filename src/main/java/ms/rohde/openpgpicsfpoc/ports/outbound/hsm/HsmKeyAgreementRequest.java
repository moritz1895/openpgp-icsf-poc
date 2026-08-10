package ms.rohde.openpgpicsfpoc.ports.outbound.hsm;

import java.util.Objects;
import ms.rohde.openpgpicsfpoc.core.domain.HsmKeyHandle;

/**
 * Unveraenderliches Ausfuehrungsobjekt fuer eine ECDH-Schluesselaustausch-
 * Operation. Wird ueber {@link HsmKeyAgreement} zusammengebaut und von
 * {@link HsmKeyAgreementExecutor} ausgefuehrt.
 *
 * <p>Sowohl der eigene private Schluessel ({@code localKeyHandle}) als auch
 * der oeffentliche Schluessel der Gegenstelle ({@code peerKeyHandle}) werden
 * ausschliesslich ueber {@link HsmKeyHandle} referenziert - diese PoC nimmt
 * an, dass Gegenstellen-Schluessel vorab im HSM als importierte
 * Public-Key-Token registriert wurden (siehe Projektplan, "Schluessel als
 * vorab im HSM vorhandene Key-Handles").</p>
 */
public record HsmKeyAgreementRequest(HsmEllipticCurve curve, HsmKeyHandle localKeyHandle, HsmKeyHandle peerKeyHandle) {

    public HsmKeyAgreementRequest {
        Objects.requireNonNull(curve, "curve darf nicht null sein");
        Objects.requireNonNull(localKeyHandle, "localKeyHandle darf nicht null sein");
        Objects.requireNonNull(peerKeyHandle, "peerKeyHandle darf nicht null sein");
    }
}
