package ms.rohde.openpgpicsfpoc.adapters.outbound.hsm.dummy;

import jakarta.inject.Inject;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Objects;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import ms.rohde.hexagonalarch.annotations.InfrastructureServiceAdapter;
import ms.rohde.openpgpicsfpoc.core.domain.ByteSequence;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmAesEncryptionExecutor;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmAesEncryptionRequest;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmAesEncryptionResult;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmCipherOperation;

/**
 * <b>Kein Produktivcode - reines Testdouble fuer den spaeteren ICSF-Adapter.</b>
 *
 * <p>Funktionale Nachbildung von {@link HsmAesEncryptionExecutor} auf Basis
 * von Standard-JDK-Crypto ({@code javax.crypto.Cipher}). Der
 * Sitzungsschluessel wird - anders als bei den asymmetrischen Primitiven -
 * direkt als Klartextwert aus der Anfrage entnommen (siehe JavaDoc auf
 * {@link HsmAesEncryptionRequest}).</p>
 */
@InfrastructureServiceAdapter
public final class DummyHsmAesEncryptionExecutor implements HsmAesEncryptionExecutor {

    private static final int GCM_TAG_LENGTH_BITS = 128;
    private static final int GCM_TAG_LENGTH_BYTES = GCM_TAG_LENGTH_BITS / 8;

    @Inject
    public DummyHsmAesEncryptionExecutor() {}

    @Override
    public HsmAesEncryptionResult execute(HsmAesEncryptionRequest request) {
        Objects.requireNonNull(request, "request darf nicht null sein");
        try {
            return switch (request.cipherMode()) {
                case ECB -> executeEcb(request);
                case CBC -> executeWithIv(request, "AES/CBC/NoPadding");
                case CFB -> executeWithIv(request, "AES/CFB/NoPadding");
                case GCM -> executeGcm(request);
            };
        } catch (GeneralSecurityException e) {
            throw new HsmDummyOperationException("AES-Operation fehlgeschlagen", e);
        }
    }

    private HsmAesEncryptionResult executeEcb(HsmAesEncryptionRequest request) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        cipher.init(cipherMode(request.operation()), secretKey(request));
        return new HsmAesEncryptionResult(ByteSequence.of(cipher.doFinal(request.input().value())), null);
    }

    private HsmAesEncryptionResult executeWithIv(HsmAesEncryptionRequest request, String transformation)
            throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(transformation);
        var iv = Objects.requireNonNull(request.initializationVector(), "initializationVector fehlt");
        cipher.init(cipherMode(request.operation()), secretKey(request), new IvParameterSpec(iv.value()));
        return new HsmAesEncryptionResult(ByteSequence.of(cipher.doFinal(request.input().value())), null);
    }

    private HsmAesEncryptionResult executeGcm(HsmAesEncryptionRequest request) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        var iv = Objects.requireNonNull(request.initializationVector(), "initializationVector fehlt");
        var gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv.value());
        cipher.init(cipherMode(request.operation()), secretKey(request), gcmSpec);
        if (request.additionalAuthenticatedData() != null) {
            cipher.updateAAD(request.additionalAuthenticatedData().value());
        }

        if (request.operation() == HsmCipherOperation.ENCRYPT) {
            byte[] outputWithTag = cipher.doFinal(request.input().value());
            int ciphertextLength = outputWithTag.length - GCM_TAG_LENGTH_BYTES;
            byte[] ciphertext = Arrays.copyOfRange(outputWithTag, 0, ciphertextLength);
            byte[] tag = Arrays.copyOfRange(outputWithTag, ciphertextLength, outputWithTag.length);
            return new HsmAesEncryptionResult(ByteSequence.of(ciphertext), ByteSequence.of(tag));
        }

        var authenticationTag = Objects.requireNonNull(request.authenticationTag(), "authenticationTag fehlt");
        byte[] ciphertextWithTag = request.input().concat(authenticationTag).value();
        return new HsmAesEncryptionResult(ByteSequence.of(cipher.doFinal(ciphertextWithTag)), null);
    }

    private static int cipherMode(HsmCipherOperation operation) {
        return operation == HsmCipherOperation.ENCRYPT ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE;
    }

    private static SecretKeySpec secretKey(HsmAesEncryptionRequest request) {
        return new SecretKeySpec(request.sessionKey().value(), "AES");
    }
}
