package ms.rohde.openpgpicsfpoc.ports.outbound.hsm;

/**
 * Von der {@link HsmAesEncryption}-Primitive unterstuetzte
 * Betriebsmodi - analog zu den nativ von CCA angebotenen Symmetric-Key-
 * Encipher/Decipher-Betriebsmodi (siehe CCA-Realitaetscheck im Projektplan).
 *
 * <ul>
 *   <li>{@link #ECB} - Einzelblock-Operation, Baustein fuer den
 *       OpenPGP-CFB-Resync bei SEIPD v1 (immer genau ein 16-Byte-Block).</li>
 *   <li>{@link #CBC}, {@link #CFB} - Blockmodi ohne Authentisierung.</li>
 *   <li>{@link #GCM} - AEAD-Modus, genutzt fuer SEIPD v2.</li>
 * </ul>
 */
public enum HsmAesCipherMode {
    ECB,
    CBC,
    CFB,
    GCM
}
