package ms.rohde.openpgpicsfpoc.adapters.outbound.openpgp.bc;

import java.io.OutputStream;
import java.security.DigestOutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;

/**
 * Lokaler SHA-1-{@link PGPDigestCalculator} fuer den Modification-Detection-Code
 * (MDC) des klassischen Verschluesselungsprofils (SEIPD v1, RFC 4880). Der
 * MDC-Digest wird ueber den <b>Klartext</b> gebildet - ein rein integritaetssicherndes,
 * nicht-geheimes Hashing ohne HSM-Bezug (analog zu
 * {@code MessageDigestCalculator} fuer Signaturen), daher lokal mit
 * {@code java.security.MessageDigest} statt einer Bouncy-Castle-Crypto-Implementierung
 * berechnet.
 */
final class LocalSha1DigestCalculator implements PGPDigestCalculator {

    private final MessageDigest digest;
    private final DigestOutputStream outputStream;

    LocalSha1DigestCalculator() {
        try {
            this.digest = MessageDigest.getInstance("SHA-1");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-1 ist auf dieser JVM nicht verfuegbar", e);
        }
        this.outputStream = new DigestOutputStream(OutputStream.nullOutputStream(), digest);
    }

    @Override
    public int getAlgorithm() {
        return HashAlgorithmTags.SHA1;
    }

    @Override
    public OutputStream getOutputStream() {
        return outputStream;
    }

    @Override
    public byte[] getDigest() {
        return digest.digest();
    }

    @Override
    public void reset() {
        digest.reset();
    }
}
