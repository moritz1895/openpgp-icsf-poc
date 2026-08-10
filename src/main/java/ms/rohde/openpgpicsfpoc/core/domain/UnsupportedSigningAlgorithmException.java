package ms.rohde.openpgpicsfpoc.core.domain;

/**
 * Wird geworfen, wenn mit einem Signaturvorgang ein Schluessel verwendet
 * wird, dessen Algorithmus laut {@link PgpPublicKeyAlgorithm#supportsSigning()}
 * keine Signaturerstellung unterstuetzt (z. B. ein reiner Verschluesselungs-
 * algorithmus wie X25519).
 */
public final class UnsupportedSigningAlgorithmException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public UnsupportedSigningAlgorithmException(PgpPublicKeyAlgorithm algorithm) {
        super("Algorithmus " + algorithm + " unterstuetzt keine Signaturerstellung");
    }
}
