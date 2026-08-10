package ms.rohde.openpgpicsfpoc.ports.outbound.hsm;

import ms.rohde.hexagonalarch.annotations.InfrastructureServicePort;

/**
 * Outbound-Port fuer die Ausfuehrung einer {@link HsmRsaEncryptionRequest}
 * gegen das HSM. Wird von Verschluesselungs-Adaptern implementiert (in
 * dieser PoC vom In-Memory-Dummy-Adapter, produktiv von einem ICSF-Adapter).
 */
@InfrastructureServicePort
public interface HsmRsaEncryptionExecutor {

    /**
     * Fuehrt die RSA-PKCS#1v1.5-Operation aus.
     */
    HsmRsaEncryptionResult execute(HsmRsaEncryptionRequest request);
}
