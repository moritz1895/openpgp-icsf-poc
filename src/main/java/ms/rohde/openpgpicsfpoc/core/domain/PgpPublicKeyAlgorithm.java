package ms.rohde.openpgpicsfpoc.core.domain;

import ms.rohde.hexagonalarch.annotations.DomainValueObject;

/**
 * Von dieser PoC unterstuetzte OpenPGP-Algorithmen fuer oeffentliche Schluessel
 * (RFC 9580 "Crypto-Refresh", das klassische ECDH-Fallback-Profil nach
 * RFC 6637 und die Post-Quantum-Erweiterung RFC 9980).
 *
 * <p>Jeder Wert traegt, ob er fuer Verschluesselung und/oder fuer Signatur
 * geeignet ist - z. B. ist {@code X25519} ein reiner Schluesselaustausch-
 * Algorithmus (nur Verschluesselung), waehrend {@code ECDSA} ein reiner
 * Signaturalgorithmus ist. Zusaetzlich traegt jeder Wert, ob er auf einem
 * lokal berechneten ECDH-Schluesselaustausch beruht ({@link #requiresSenderKeyAgreementKey()})
 * - {@code X25519}, {@code ECDH} und {@code ML_KEM_768_X25519} benoetigen
 * dafuer einen eigenen Sender-Schluessel (siehe {@code EncryptOpenPgpMessageCommand}).</p>
 *
 * <p>{@link #X25519} bildet das native, kurvenfeste RFC-9580-Profil ab;
 * {@link #ECDH} das klassische, kurvenparametrisierte Fallback-Profil nach
 * RFC 6637 (NIST P-256/P-384 etc.) - die konkrete Kurve eines ECDH-Schluessels
 * wird auf {@link PgpPublicKey#curve()} abgebildet.</p>
 */
@DomainValueObject
public enum PgpPublicKeyAlgorithm {

    RSA(true, true, false),
    ECDSA(false, true, false),
    EDDSA(false, true, false),
    X25519(true, false, true),
    ECDH(true, false, true),
    ML_KEM_768_X25519(true, false, true),
    ML_DSA_65_ED25519(false, true, false);

    private final boolean encryptionCapable;
    private final boolean signingCapable;
    private final boolean keyAgreementBased;

    PgpPublicKeyAlgorithm(boolean encryptionCapable, boolean signingCapable, boolean keyAgreementBased) {
        this.encryptionCapable = encryptionCapable;
        this.signingCapable = signingCapable;
        this.keyAgreementBased = keyAgreementBased;
    }

    public boolean supportsEncryption() {
        return encryptionCapable;
    }

    public boolean supportsSigning() {
        return signingCapable;
    }

    /**
     * Liefert {@code true}, wenn dieser Algorithmus fuer die Verschluesselung
     * einen eigenen (vorab im HSM vorhandenen) Sender-Schluessel fuer einen
     * lokal berechneten ECDH-Schluesselaustausch benoetigt - X25519, das
     * klassische ECDH-Fallback-Profil sowie die klassische Komponente des
     * kompositen PQC-Verfahrens.
     */
    public boolean requiresSenderKeyAgreementKey() {
        return keyAgreementBased;
    }
}
