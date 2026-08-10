package ms.rohde.openpgpicsfpoc.core.domain;

/**
 * Wird geworfen, wenn fuer einen Empfaenger-Schluessel eine Verschluesselung
 * angefordert wird, dessen Algorithmus laut {@link PgpPublicKeyAlgorithm#supportsEncryption()}
 * keine Verschluesselung unterstuetzt (z. B. ein reiner Signaturalgorithmus).
 */
public final class UnsupportedEncryptionAlgorithmException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public UnsupportedEncryptionAlgorithmException(PgpPublicKeyAlgorithm algorithm) {
        super("Algorithmus " + algorithm + " unterstuetzt keine Verschluesselung");
    }
}
