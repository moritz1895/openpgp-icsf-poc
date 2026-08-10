package ms.rohde.openpgpicsfpoc.ports.outbound.hsm;

import ms.rohde.hexagonalarch.annotations.InfrastructureServicePort;

/**
 * Outbound-Port fuer die Ausfuehrung einer {@link HsmSignatureRequest} gegen
 * das HSM. Verifikation ist hingegen eine reine Public-Key-Operation ohne
 * Geheimnis und benoetigt daher keinen HSM-Port (siehe Projektplan).
 */
@InfrastructureServicePort
public interface HsmSignatureExecutor {

    /**
     * Signiert den uebergebenen (lokal berechneten) Digest.
     */
    HsmSignatureResult execute(HsmSignatureRequest request);
}
