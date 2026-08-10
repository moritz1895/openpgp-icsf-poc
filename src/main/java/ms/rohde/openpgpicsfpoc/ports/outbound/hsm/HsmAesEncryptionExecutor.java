package ms.rohde.openpgpicsfpoc.ports.outbound.hsm;

import ms.rohde.hexagonalarch.annotations.InfrastructureServicePort;

/**
 * Outbound-Port fuer die Ausfuehrung einer {@link HsmAesEncryptionRequest}
 * gegen das HSM. Wird sowohl fuer AEAD-Verschluesselung (SEIPD v2, GCM) als
 * auch fuer Einzelblock-ECB-Operationen (Baustein fuer den OpenPGP-CFB-
 * Resync bei SEIPD v1) genutzt.
 */
@InfrastructureServicePort
public interface HsmAesEncryptionExecutor {

    /**
     * Fuehrt die AES-Operation im angeforderten Betriebsmodus aus.
     */
    HsmAesEncryptionResult execute(HsmAesEncryptionRequest request);
}
