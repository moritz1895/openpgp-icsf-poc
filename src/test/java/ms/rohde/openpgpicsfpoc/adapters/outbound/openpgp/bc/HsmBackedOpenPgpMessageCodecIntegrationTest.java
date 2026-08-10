package ms.rohde.openpgpicsfpoc.adapters.outbound.openpgp.bc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import ms.rohde.openpgpicsfpoc.core.domain.ByteSequence;
import ms.rohde.openpgpicsfpoc.core.domain.HsmKeyHandle;
import ms.rohde.openpgpicsfpoc.core.domain.OpenPgpMessage;
import ms.rohde.openpgpicsfpoc.core.domain.PgpEllipticCurve;
import ms.rohde.openpgpicsfpoc.core.domain.PgpEncryptionProfile;
import ms.rohde.openpgpicsfpoc.core.domain.PgpKeyReference;
import ms.rohde.openpgpicsfpoc.ports.outbound.OpenPgpDecryptionRequest;
import ms.rohde.openpgpicsfpoc.ports.outbound.OpenPgpEncryptionRequest;
import ms.rohde.openpgpicsfpoc.ports.outbound.OpenPgpSigningRequest;
import ms.rohde.openpgpicsfpoc.ports.outbound.OpenPgpVerificationRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * Vollstaendige Rundlauf-Integrationstests der Bouncy-Castle-Bridge ueber die
 * Dummy-Hsm-Adapter (siehe {@link HsmTestFixture}) - fuer jede
 * Algorithmus-/Profil-Kombination dieser Iteration (RSA, natives X25519,
 * klassisches ECDH-Fallback ueber P-256, jeweils Legacy-CFB+MDC und
 * AEAD/GCM) sowie fuer Signieren/Verifizieren (RSA, ECDSA, EdDSA).
 */
class HsmBackedOpenPgpMessageCodecIntegrationTest {

    private static final ByteSequence PLAINTEXT = ByteSequence.of("Hallo HSM-gestuetztes OpenPGP!".getBytes());

    @ParameterizedTest
    @EnumSource(PgpEncryptionProfile.class)
    void encryptThenDecrypt_givenRsaRecipient_thenRecoversPlaintext(PgpEncryptionProfile profile) throws Exception {
        var fixture = new HsmTestFixture();
        var keyPair = PgpTestKeys.generateRsa();
        var recipient = fixture.registerRecipient("bob-rsa", keyPair, PgpTestKeys.rsaPublicKey(keyPair));

        OpenPgpMessage encrypted =
                fixture.codec.encrypt(new OpenPgpEncryptionRequest(PLAINTEXT, profile, recipient, null));
        ByteSequence decrypted = fixture.codec.decrypt(new OpenPgpDecryptionRequest(encrypted, recipient));

        assertThat(decrypted).isEqualTo(PLAINTEXT);
    }

    @ParameterizedTest
    @EnumSource(PgpEncryptionProfile.class)
    void encryptThenDecrypt_givenNativeX25519Recipient_thenRecoversPlaintext(PgpEncryptionProfile profile)
            throws Exception {
        var fixture = new HsmTestFixture();
        var recipientKeyPair = PgpTestKeys.generateX25519();
        var recipient = fixture.registerRecipient(
                "bob-x25519", recipientKeyPair, PgpTestKeys.x25519PublicKey(recipientKeyPair));
        var senderKeyPair = PgpTestKeys.generateX25519();
        var sender = fixture.registerSenderKeyAgreementKey(
                "alice-x25519", senderKeyPair, PgpTestKeys.x25519PublicKey(senderKeyPair));

        OpenPgpMessage encrypted =
                fixture.codec.encrypt(new OpenPgpEncryptionRequest(PLAINTEXT, profile, recipient, sender));
        ByteSequence decrypted = fixture.codec.decrypt(new OpenPgpDecryptionRequest(encrypted, recipient));

        assertThat(decrypted).isEqualTo(PLAINTEXT);
    }

    @ParameterizedTest
    @EnumSource(PgpEncryptionProfile.class)
    void encryptThenDecrypt_givenClassicalEcdhP256Recipient_thenRecoversPlaintext(PgpEncryptionProfile profile)
            throws Exception {
        var fixture = new HsmTestFixture();
        var recipientKeyPair = PgpTestKeys.generateEc(PgpEllipticCurve.P256);
        var recipient = fixture.registerRecipient(
                "bob-p256", recipientKeyPair, PgpTestKeys.ecdhPublicKey(recipientKeyPair, PgpEllipticCurve.P256));
        var senderKeyPair = PgpTestKeys.generateEc(PgpEllipticCurve.P256);
        var sender = fixture.registerSenderKeyAgreementKey(
                "alice-p256", senderKeyPair, PgpTestKeys.ecdhPublicKey(senderKeyPair, PgpEllipticCurve.P256));

        OpenPgpMessage encrypted =
                fixture.codec.encrypt(new OpenPgpEncryptionRequest(PLAINTEXT, profile, recipient, sender));
        ByteSequence decrypted = fixture.codec.decrypt(new OpenPgpDecryptionRequest(encrypted, recipient));

        assertThat(decrypted).isEqualTo(PLAINTEXT);
    }

    @Test
    void encryptThenDecrypt_givenClassicalEcdhP384Recipient_thenRecoversPlaintext() throws Exception {
        var fixture = new HsmTestFixture();
        var recipientKeyPair = PgpTestKeys.generateEc(PgpEllipticCurve.P384);
        var recipient = fixture.registerRecipient(
                "bob-p384", recipientKeyPair, PgpTestKeys.ecdhPublicKey(recipientKeyPair, PgpEllipticCurve.P384));
        var senderKeyPair = PgpTestKeys.generateEc(PgpEllipticCurve.P384);
        var sender = fixture.registerSenderKeyAgreementKey(
                "alice-p384", senderKeyPair, PgpTestKeys.ecdhPublicKey(senderKeyPair, PgpEllipticCurve.P384));

        OpenPgpMessage encrypted = fixture.codec.encrypt(
                new OpenPgpEncryptionRequest(PLAINTEXT, PgpEncryptionProfile.LEGACY_CFB_MDC, recipient, sender));
        ByteSequence decrypted = fixture.codec.decrypt(new OpenPgpDecryptionRequest(encrypted, recipient));

        assertThat(decrypted).isEqualTo(PLAINTEXT);
    }

    @Test
    void decrypt_givenWrongRecipientKey_thenThrowsDecryptionFailedException() throws Exception {
        var fixture = new HsmTestFixture();
        var keyPair = PgpTestKeys.generateRsa();
        var recipient = fixture.registerRecipient("bob-rsa", keyPair, PgpTestKeys.rsaPublicKey(keyPair));
        var wrongKeyPair = PgpTestKeys.generateRsa();
        var wrongRecipient =
                new PgpKeyReference(new HsmKeyHandle("bob-rsa-wrong"), PgpTestKeys.rsaPublicKey(wrongKeyPair));
        fixture.keyStore.registerKeyPair(new HsmKeyHandle("bob-rsa-wrong"), wrongKeyPair);

        OpenPgpMessage encrypted = fixture.codec.encrypt(
                new OpenPgpEncryptionRequest(PLAINTEXT, PgpEncryptionProfile.LEGACY_CFB_MDC, recipient, null));

        assertThatThrownBy(() -> fixture.codec.decrypt(new OpenPgpDecryptionRequest(encrypted, wrongRecipient)))
                .isInstanceOf(OpenPgpDecryptionFailedException.class);
    }

    @Test
    void signThenVerify_givenRsaSigner_thenVerificationSucceeds() throws Exception {
        var fixture = new HsmTestFixture();
        var keyPair = PgpTestKeys.generateRsa();
        var signer = fixture.registerRecipient("signer-rsa", keyPair, PgpTestKeys.rsaPublicKey(keyPair));

        OpenPgpMessage signed = fixture.codec.sign(new OpenPgpSigningRequest(PLAINTEXT, signer));
        boolean valid = fixture.codec.verify(new OpenPgpVerificationRequest(signed, signer.publicKey()));

        assertThat(valid).isTrue();
    }

    @Test
    void signThenVerify_givenEcdsaSigner_thenVerificationSucceeds() throws Exception {
        var fixture = new HsmTestFixture();
        var keyPair = PgpTestKeys.generateEc(PgpEllipticCurve.P256);
        var signer = fixture.registerRecipient(
                "signer-ecdsa", keyPair, PgpTestKeys.ecdsaPublicKey(keyPair, PgpEllipticCurve.P256));

        OpenPgpMessage signed = fixture.codec.sign(new OpenPgpSigningRequest(PLAINTEXT, signer));
        boolean valid = fixture.codec.verify(new OpenPgpVerificationRequest(signed, signer.publicKey()));

        assertThat(valid).isTrue();
    }

    @Test
    void signThenVerify_givenEd25519Signer_thenVerificationSucceeds() throws Exception {
        var fixture = new HsmTestFixture();
        var keyPair = PgpTestKeys.generateEd25519();
        var signer = fixture.registerRecipient("signer-ed25519", keyPair, PgpTestKeys.eddsaPublicKey(keyPair));

        OpenPgpMessage signed = fixture.codec.sign(new OpenPgpSigningRequest(PLAINTEXT, signer));
        boolean valid = fixture.codec.verify(new OpenPgpVerificationRequest(signed, signer.publicKey()));

        assertThat(valid).isTrue();
    }

    @Test
    void verify_givenWrongSignerPublicKey_thenReturnsFalse() throws Exception {
        var fixture = new HsmTestFixture();
        var keyPair = PgpTestKeys.generateRsa();
        var signer = fixture.registerRecipient("signer-rsa", keyPair, PgpTestKeys.rsaPublicKey(keyPair));
        var otherKeyPair = PgpTestKeys.generateRsa();

        OpenPgpMessage signed = fixture.codec.sign(new OpenPgpSigningRequest(PLAINTEXT, signer));
        boolean valid = fixture.codec.verify(
                new OpenPgpVerificationRequest(signed, PgpTestKeys.rsaPublicKey(otherKeyPair)));

        assertThat(valid).isFalse();
    }
}
