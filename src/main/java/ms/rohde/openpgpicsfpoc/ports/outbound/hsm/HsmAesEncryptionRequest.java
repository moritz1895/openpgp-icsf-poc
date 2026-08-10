package ms.rohde.openpgpicsfpoc.ports.outbound.hsm;

import java.util.Objects;
import ms.rohde.openpgpicsfpoc.core.domain.ByteSequence;
import org.jspecify.annotations.Nullable;

/**
 * Unveraenderliches Ausfuehrungsobjekt fuer eine AES-Operation. Wird ueber
 * {@link HsmAesEncryption} zusammengebaut und von
 * {@link HsmAesEncryptionExecutor} ausgefuehrt.
 *
 * <p><b>Abweichung von der sonst geltenden Handle-only-Regel:</b> anders als
 * RSA-, Signatur-, Schluesselaustausch- und Schluesselkapselungs-Operationen,
 * die stets langlebiges asymmetrisches Schluesselmaterial adressieren und
 * daher ausschliesslich ueber {@link ms.rohde.openpgpicsfpoc.core.domain.HsmKeyHandle}
 * referenziert werden, traegt diese Primitive den AES-Sitzungsschluessel als
 * rohen {@link ByteSequence}-Wert. Der Sitzungsschluessel ist in dieser PoC
 * ephemer, wird pro Nachricht neu erzeugt (siehe
 * {@code SymmetricSessionKeyGenerator}, mangels Hsm-Keygen-Port lokal) und
 * ohnehin unmittelbar fuer den/die Empfaenger verpackt - eine vorherige
 * Registrierung als HSM-Handle wuerde einen in dieser PoC nicht vorhandenen
 * Key-Import-Port voraussetzen. Das entspricht dem "Clear-Key"-Betriebsmodus
 * realer symmetrischer HSM-Verben (z. B. CCA Symmetric Key Encipher/Decipher
 * mit Klartextschluessel) im Gegensatz zu deren "Secure-Key"-Varianten.</p>
 */
public record HsmAesEncryptionRequest(
        ByteSequence sessionKey,
        HsmAesCipherMode cipherMode,
        HsmCipherOperation operation,
        ByteSequence input,
        @Nullable ByteSequence initializationVector,
        @Nullable ByteSequence additionalAuthenticatedData,
        @Nullable ByteSequence authenticationTag) {

    private static final int SINGLE_BLOCK_LENGTH = 16;

    public HsmAesEncryptionRequest {
        Objects.requireNonNull(sessionKey, "sessionKey darf nicht null sein");
        Objects.requireNonNull(cipherMode, "cipherMode darf nicht null sein");
        Objects.requireNonNull(operation, "operation darf nicht null sein");
        Objects.requireNonNull(input, "input darf nicht null sein");
        if (sessionKey.isEmpty()) {
            throw new IllegalArgumentException("sessionKey darf nicht leer sein");
        }
        if (input.isEmpty()) {
            throw new IllegalArgumentException("input darf nicht leer sein");
        }

        switch (cipherMode) {
            case ECB -> {
                if (initializationVector != null) {
                    throw new IllegalArgumentException("ECB darf keinen initializationVector haben");
                }
                if (input.length() != SINGLE_BLOCK_LENGTH) {
                    throw new IllegalArgumentException(
                            "ECB wird in dieser Primitive ausschliesslich als Einzelblock-Operation (16 Byte) genutzt");
                }
            }
            case CBC, CFB -> {
                if (initializationVector == null) {
                    throw new IllegalArgumentException(cipherMode + " benoetigt einen initializationVector");
                }
            }
            case GCM -> {
                if (initializationVector == null) {
                    throw new IllegalArgumentException("GCM benoetigt einen initializationVector (Nonce)");
                }
                if (operation == HsmCipherOperation.DECRYPT && authenticationTag == null) {
                    throw new IllegalArgumentException("GCM-Entschluesselung benoetigt authenticationTag");
                }
            }
        }
    }
}
