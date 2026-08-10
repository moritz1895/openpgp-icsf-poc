package ms.rohde.openpgpicsfpoc.ports.outbound.hsm;

import ms.rohde.hexagonalarch.annotations.InfrastructureServicePort;

/**
 * Outbound-Port fuer die Ausfuehrung einer {@link HsmKeyAgreementRequest}
 * gegen das HSM. Deckt sowohl klassische ECC-Verschluesselung als auch die
 * ECDH-Haelfte der kompositen PQC-Verschluesselung (ML-KEM-768+X25519) ab.
 */
@InfrastructureServicePort
public interface HsmKeyAgreementExecutor {

    /**
     * Leitet das ECDH-Shared-Secret ab.
     */
    HsmKeyAgreementResult execute(HsmKeyAgreementRequest request);
}
