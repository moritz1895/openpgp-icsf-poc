package ms.rohde.openpgpicsfpoc.ports.outbound.hsm;

import java.util.Objects;
import ms.rohde.openpgpicsfpoc.core.domain.ByteSequence;
import ms.rohde.openpgpicsfpoc.core.domain.HsmKeyHandle;

/**
 * Unveraenderliches Ausfuehrungsobjekt fuer eine RSA-PKCS#1v1.5-Operation.
 * Wird ueber {@link HsmRsaEncryption} zusammengebaut und von
 * {@link HsmRsaEncryptionExecutor} ausgefuehrt.
 *
 * <p>Der referenzierte Schluessel wird ausschliesslich ueber
 * {@link HsmKeyHandle} adressiert - bei {@link HsmCipherOperation#ENCRYPT}
 * der (vorab im HSM registrierte) oeffentliche Schluessel der Gegenstelle,
 * bei {@link HsmCipherOperation#DECRYPT} der eigene private Schluessel.</p>
 */
public record HsmRsaEncryptionRequest(HsmKeyHandle keyHandle, HsmCipherOperation operation, ByteSequence input) {

    public HsmRsaEncryptionRequest {
        Objects.requireNonNull(keyHandle, "keyHandle darf nicht null sein");
        Objects.requireNonNull(operation, "operation darf nicht null sein");
        Objects.requireNonNull(input, "input darf nicht null sein");
        if (input.isEmpty()) {
            throw new IllegalArgumentException("input darf nicht leer sein");
        }
    }
}
