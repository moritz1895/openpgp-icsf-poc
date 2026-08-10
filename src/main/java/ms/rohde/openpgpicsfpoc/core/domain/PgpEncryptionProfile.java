package ms.rohde.openpgpicsfpoc.core.domain;

import ms.rohde.hexagonalarch.annotations.DomainValueObject;

/**
 * Verschluesselungsprofil einer OpenPGP-Nachricht.
 *
 * <ul>
 *   <li>{@link #LEGACY_CFB_MDC} - klassisches Profil nach RFC 4880 (Symmetrically
 *       Encrypted Integrity Protected Data, CFB-Modus mit angehaengtem MDC).</li>
 *   <li>{@link #AEAD_V2} - modernes Profil nach RFC 9580 (SEIPD Version 2,
 *       AEAD mit AES-256-GCM statt OCB, siehe CCA-Realitaetscheck im Projektplan).</li>
 * </ul>
 */
@DomainValueObject
public enum PgpEncryptionProfile {
    LEGACY_CFB_MDC,
    AEAD_V2
}
