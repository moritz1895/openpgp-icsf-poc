package ms.rohde.openpgpicsfpoc.core.domain;

/**
 * Wird geworfen, wenn fuer einen schluesselaustausch-basierten Algorithmus
 * ({@link PgpPublicKeyAlgorithm#requiresSenderKeyAgreementKey()}: natives
 * X25519, klassisches ECDH-Fallback-Profil oder das komposite
 * ML-KEM-768+X25519-Verfahren) kein eigener Sender-Schluessel fuer den
 * ECDH-Schluesselaustausch angegeben wurde.
 *
 * <p>Diese PoC verwendet mangels Hsm-Keygen-Port bewusst einen vorab im HSM
 * vorhandenen (statischen) Sender-Schluessel statt eines je Nachricht neu
 * erzeugten ephemeren Schluessels - siehe JavaDoc auf
 * {@code EncryptOpenPgpMessageCommand}.</p>
 */
public final class MissingKeyAgreementKeyException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public MissingKeyAgreementKeyException(PgpPublicKeyAlgorithm algorithm) {
        super("Fuer Algorithmus " + algorithm + " wird ein Sender-Schluessel fuer den Schluesselaustausch benoetigt");
    }
}
