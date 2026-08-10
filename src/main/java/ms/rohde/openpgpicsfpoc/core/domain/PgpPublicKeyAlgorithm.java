package ms.rohde.openpgpicsfpoc.core.domain;

import ms.rohde.hexagonalarch.annotations.DomainValueObject;

/**
 * Von dieser PoC unterstuetzte OpenPGP-Algorithmen fuer oeffentliche Schluessel
 * (RFC 9580 "Crypto-Refresh" und die Post-Quantum-Erweiterung RFC 9980).
 *
 * <p>Jeder Wert traegt, ob er fuer Verschluesselung und/oder fuer Signatur
 * geeignet ist - z. B. ist {@code X25519} ein reiner Schluesselaustausch-
 * Algorithmus (nur Verschluesselung), waehrend {@code ECDSA} ein reiner
 * Signaturalgorithmus ist.</p>
 */
@DomainValueObject
public enum PgpPublicKeyAlgorithm {

    RSA(true, true),
    ECDSA(false, true),
    EDDSA(false, true),
    X25519(true, false),
    ML_KEM_768_X25519(true, false),
    ML_DSA_65_ED25519(false, true);

    private final boolean encryptionCapable;
    private final boolean signingCapable;

    PgpPublicKeyAlgorithm(boolean encryptionCapable, boolean signingCapable) {
        this.encryptionCapable = encryptionCapable;
        this.signingCapable = signingCapable;
    }

    public boolean supportsEncryption() {
        return encryptionCapable;
    }

    public boolean supportsSigning() {
        return signingCapable;
    }
}
