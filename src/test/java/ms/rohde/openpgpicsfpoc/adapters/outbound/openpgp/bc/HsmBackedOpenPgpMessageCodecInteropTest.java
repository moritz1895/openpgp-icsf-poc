package ms.rohde.openpgpicsfpoc.adapters.outbound.openpgp.bc;

import static org.assertj.core.api.Assertions.assertThat;

import ms.rohde.openpgpicsfpoc.core.domain.ByteSequence;
import ms.rohde.openpgpicsfpoc.core.domain.OpenPgpMessage;
import ms.rohde.openpgpicsfpoc.ports.outbound.OpenPgpEncryptionRequest;
import ms.rohde.openpgpicsfpoc.ports.outbound.OpenPgpSigningRequest;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.junit.jupiter.api.Test;

/**
 * Zentraler Interoperabilitaets-Nachweis dieser PoC: eine mit der
 * HSM-gestuetzten Bridge erzeugte Nachricht wird ausschliesslich mit
 * <b>unveraendertem</b> Bouncy-Castle-Standard-API gelesen - ohne jede
 * Kenntnis dieses Projekts, ohne HSM-Bezug, nur mit dem rohen
 * JCA-Schluesselmaterial. Das belegt, dass die von der Bridge erzeugten
 * Nachrichten tatsaechlich standardkonformes OpenPGP sind (siehe Projektplan,
 * Abschnitt "Verifikation").
 *
 * <p>Diese Testklasse registriert {@link BouncyCastleProvider} als
 * JCE-Provider - ausschliesslich um die Rolle eines unabhaengigen,
 * standardkonformen Fremdwerkzeugs zu simulieren (fuer AES-256-GCM/SEIPD-v2
 * benoetigt Bouncy Castles {@code JcePublicKeyDataDecryptorFactoryBuilder}
 * einen "HKDF-SHA256"-{@code SecretKeyFactory}, den kein Standard-JDK-Provider
 * mitbringt). Die eigentliche Bridge-Produktivimplementierung
 * ({@code adapters.outbound.openpgp.bc}) registriert diesen Provider an
 * keiner Stelle (siehe Projektplan: "niemals BouncyCastleProvider als
 * JCE-Provider registrieren").</p>
 */
class HsmBackedOpenPgpMessageCodecInteropTest {

    static {
        java.security.Security.addProvider(new BouncyCastleProvider());
    }

    private static final ByteSequence PLAINTEXT = ByteSequence.of("Interop-Nachweis: unveraendertes Bouncy Castle liest diese Nachricht.".getBytes());
    private static final BcKeyFingerprintCalculator FINGERPRINT_CALCULATOR = new BcKeyFingerprintCalculator();

    @Test
    void encrypt_givenRsaRecipient_thenStandardJceDecryptorRecoversPlaintext() throws Exception {
        var fixture = new HsmTestFixture();
        var keyPair = PgpTestKeys.generateRsa();
        var recipient = fixture.registerRecipient("bob-rsa", keyPair, PgpTestKeys.rsaPublicKey(keyPair));

        OpenPgpMessage encrypted = fixture.codec.encrypt(new OpenPgpEncryptionRequest(PLAINTEXT, recipient, null));

        byte[] plaintext = decryptWithStandardBouncyCastle(encrypted, keyPair.getPrivate());

        assertThat(plaintext).isEqualTo(PLAINTEXT.value());
    }

    @Test
    void sign_givenRsaSigner_thenStandardJcaVerifierAcceptsSignature() throws Exception {
        var fixture = new HsmTestFixture();
        var keyPair = PgpTestKeys.generateRsa();
        var signer = fixture.registerRecipient("signer-rsa", keyPair, PgpTestKeys.rsaPublicKey(keyPair));

        OpenPgpMessage signed = fixture.codec.sign(new OpenPgpSigningRequest(PLAINTEXT, signer));

        assertThat(verifyWithStandardBouncyCastle(signed, signer.publicKey())).isTrue();
    }

    @Test
    void sign_givenEcdsaSigner_thenStandardJcaVerifierAcceptsSignature() throws Exception {
        var fixture = new HsmTestFixture();
        var keyPair = PgpTestKeys.generateEc(ms.rohde.openpgpicsfpoc.core.domain.PgpEllipticCurve.P256);
        var signer = fixture.registerRecipient(
                "signer-ecdsa", keyPair,
                PgpTestKeys.ecdsaPublicKey(keyPair, ms.rohde.openpgpicsfpoc.core.domain.PgpEllipticCurve.P256));

        OpenPgpMessage signed = fixture.codec.sign(new OpenPgpSigningRequest(PLAINTEXT, signer));

        assertThat(verifyWithStandardBouncyCastle(signed, signer.publicKey())).isTrue();
    }

    private static byte[] decryptWithStandardBouncyCastle(
            OpenPgpMessage message, java.security.PrivateKey standardJcaPrivateKey) throws Exception {
        var factory = new PGPObjectFactory(message.encoded().value(), FINGERPRINT_CALCULATOR);
        Object next = factory.nextObject();
        while (!(next instanceof PGPEncryptedDataList)) {
            next = factory.nextObject();
        }
        var encryptedDataList = (PGPEncryptedDataList) next;
        PGPPublicKeyEncryptedData encryptedData = null;
        for (var data : encryptedDataList) {
            if (data instanceof PGPPublicKeyEncryptedData candidate) {
                encryptedData = candidate;
            }
        }
        assertThat(encryptedData).isNotNull();

        var decryptorFactory = new JcePublicKeyDataDecryptorFactoryBuilder().build(standardJcaPrivateKey);
        try (var decryptedStream = encryptedData.getDataStream(decryptorFactory)) {
            var innerFactory = new PGPObjectFactory(decryptedStream, FINGERPRINT_CALCULATOR);
            Object innerNext = innerFactory.nextObject();
            while (!(innerNext instanceof PGPLiteralData)) {
                innerNext = innerFactory.nextObject();
            }
            return ((PGPLiteralData) innerNext).getInputStream().readAllBytes();
        }
    }

    private static boolean verifyWithStandardBouncyCastle(
            OpenPgpMessage signedMessage, ms.rohde.openpgpicsfpoc.core.domain.PgpPublicKey signerPublicKey)
            throws Exception {
        var factory = new PGPObjectFactory(signedMessage.encoded().value(), FINGERPRINT_CALCULATOR);
        Object current = factory.nextObject();
        if (current instanceof org.bouncycastle.openpgp.PGPOnePassSignatureList) {
            current = factory.nextObject();
        }
        var literalData = (PGPLiteralData) current;
        byte[] content = literalData.getInputStream().readAllBytes();

        var signatureList = (PGPSignatureList) factory.nextObject();
        PGPSignature signature = signatureList.get(0);

        var pgpPublicKey = PgpKeyMaterialCodec.toPgpPublicKey(signerPublicKey, FINGERPRINT_CALCULATOR);
        signature.init(new JcaPGPContentVerifierBuilderProvider(), pgpPublicKey);
        signature.update(content);
        return signature.verify();
    }
}
