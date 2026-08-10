package ms.rohde.openpgpicsfpoc.ports.outbound.hsm;

import ms.rohde.hexagonalarch.annotations.InfrastructureServicePort;

/**
 * Outbound-Port fuer die Ausfuehrung einer {@link HsmKeyEncapsulationRequest}
 * gegen das HSM (ML-KEM-768 Encapsulate/Decapsulate fuer die PQC-Haelfte
 * der kompositen Verschluesselung ML-KEM-768+X25519).
 */
@InfrastructureServicePort
public interface HsmKeyEncapsulationExecutor {

    /**
     * Fuehrt Encapsulate oder Decapsulate aus, je nach
     * {@link HsmKeyEncapsulationRequest#operation()}.
     */
    HsmKeyEncapsulationResult execute(HsmKeyEncapsulationRequest request);
}
