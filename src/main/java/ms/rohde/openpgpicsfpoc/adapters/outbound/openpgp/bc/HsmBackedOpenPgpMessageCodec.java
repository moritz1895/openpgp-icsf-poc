package ms.rohde.openpgpicsfpoc.adapters.outbound.openpgp.bc;

import jakarta.inject.Inject;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Objects;
import ms.rohde.hexagonalarch.annotations.InfrastructureServiceAdapter;
import ms.rohde.openpgpicsfpoc.core.domain.ByteSequence;
import ms.rohde.openpgpicsfpoc.core.domain.OpenPgpMessage;
import ms.rohde.openpgpicsfpoc.core.domain.PgpEncryptionProfile;
import ms.rohde.openpgpicsfpoc.core.domain.PgpKeyReference;
import ms.rohde.openpgpicsfpoc.core.domain.PgpPublicKey;
import ms.rohde.openpgpicsfpoc.core.domain.PgpPublicKeyAlgorithm;
import ms.rohde.openpgpicsfpoc.ports.outbound.OpenPgpDecryptionRequest;
import ms.rohde.openpgpicsfpoc.ports.outbound.OpenPgpEncryptionRequest;
import ms.rohde.openpgpicsfpoc.ports.outbound.OpenPgpMessageCodec;
import ms.rohde.openpgpicsfpoc.ports.outbound.OpenPgpSigningRequest;
import ms.rohde.openpgpicsfpoc.ports.outbound.OpenPgpVerificationRequest;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmAesEncryptionExecutor;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmKeyAgreementExecutor;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmRsaEncryptionExecutor;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmSignatureExecutor;
import org.bouncycastle.bcpg.AEADAlgorithmTags;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.operator.PGPKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;

/**
 * Bouncy-Castle-Bridge-Implementierung von {@link OpenPgpMessageCodec}: setzt
 * die einzelnen Bridge-Klassen dieses Pakets zu vollstaendigen
 * {@code encrypt}/{@code decrypt}/{@code sign}/{@code verify}-Ablaeufen
 * zusammen. Bouncy Castle wird ausschliesslich fuer Paket-Framing und
 * Orchestrierung genutzt ({@link org.bouncycastle.openpgp.PGPEncryptedDataGenerator},
 * {@link PGPSignatureGenerator}, {@link PGPObjectFactory}, ...) - jede
 * tatsaechliche kryptographische Operation laeuft ueber die injizierten
 * Hsm-Executor-Ports (siehe Projektplan, Abschnitt "Kernidee der technischen
 * Loesung").
 *
 * <p><b>Scope dieser Iteration:</b> RSA sowie ECC (natives X25519/Ed25519 nach
 * RFC 9580 und das klassische ECDH/ECDSA-Fallback-Profil nach RFC 6637) -
 * die Post-Quantum-Komposit-Algorithmen (ML-KEM-768+X25519, ML-DSA-65+Ed25519)
 * sind explizit ausserhalb des Scopes (siehe Aufgabenstellung).</p>
 */
@InfrastructureServiceAdapter
public final class HsmBackedOpenPgpMessageCodec implements OpenPgpMessageCodec {

    private static final int AEAD_CHUNK_SIZE_EXPONENT = 12; // 4096-Byte-Chunks
    private static final BcKeyFingerprintCalculator FINGERPRINT_CALCULATOR = new BcKeyFingerprintCalculator();

    private final HsmRsaEncryptionExecutor rsaExecutor;
    private final HsmAesEncryptionExecutor aesExecutor;
    private final HsmKeyAgreementExecutor keyAgreementExecutor;
    private final HsmSignatureExecutor signatureExecutor;

    @Inject
    public HsmBackedOpenPgpMessageCodec(
            HsmRsaEncryptionExecutor rsaExecutor,
            HsmAesEncryptionExecutor aesExecutor,
            HsmKeyAgreementExecutor keyAgreementExecutor,
            HsmSignatureExecutor signatureExecutor) {
        this.rsaExecutor = Objects.requireNonNull(rsaExecutor, "rsaExecutor darf nicht null sein");
        this.aesExecutor = Objects.requireNonNull(aesExecutor, "aesExecutor darf nicht null sein");
        this.keyAgreementExecutor = Objects.requireNonNull(keyAgreementExecutor, "keyAgreementExecutor darf nicht null sein");
        this.signatureExecutor = Objects.requireNonNull(signatureExecutor, "signatureExecutor darf nicht null sein");
    }

    @Override
    public OpenPgpMessage encrypt(OpenPgpEncryptionRequest request) {
        try {
            var recipientPublicKey = request.recipient().publicKey();
            var recipientPgpPublicKey = PgpKeyMaterialCodec.toPgpPublicKey(recipientPublicKey);

            var dataEncryptorBuilder = new HsmBackedPGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256, aesExecutor);
            if (request.profile() == PgpEncryptionProfile.AEAD_V2) {
                dataEncryptorBuilder.setWithAEAD(AEADAlgorithmTags.GCM, AEAD_CHUNK_SIZE_EXPONENT);
                dataEncryptorBuilder.setUseV6AEAD();
            } else {
                dataEncryptorBuilder.setWithIntegrityPacket(true);
            }

            var generator = new org.bouncycastle.openpgp.PGPEncryptedDataGenerator(dataEncryptorBuilder);
            generator.addMethod(methodGeneratorFor(recipientPublicKey, recipientPgpPublicKey, request));

            byte[] plaintext = request.plaintext().value();
            var outputBytes = new ByteArrayOutputStream();
            // Partial-Body-Length-Modus (statt fester Laenge): der ueber diesen Stream
            // geschriebene Byteumfang ist die Groesse des GESAMTEN Literal-Data-Pakets
            // (Paket-Header + Inhalt), nicht nur die des rohen Klartexts - im
            // Partial-Body-Modus muss diese Differenz nicht vorab berechnet werden.
            try (OutputStream encryptedOut = generator.open(outputBytes, new byte[1 << 16])) {
                writeLiteralData(encryptedOut, plaintext);
            }
            return new OpenPgpMessage(ByteSequence.of(outputBytes.toByteArray()));
        } catch (PGPException | IOException e) {
            throw new OpenPgpMessageCodecException("Verschluesselung fehlgeschlagen: " + e.getMessage(), e);
        }
    }

    private PGPKeyEncryptionMethodGenerator methodGeneratorFor(
            PgpPublicKey recipientPublicKey,
            org.bouncycastle.openpgp.PGPPublicKey recipientPgpPublicKey,
            OpenPgpEncryptionRequest request) {
        var algorithm = recipientPublicKey.algorithm();
        if (algorithm == PgpPublicKeyAlgorithm.RSA) {
            return new HsmRsaPublicKeyKeyEncryptionMethodGenerator(
                    recipientPgpPublicKey, rsaExecutor, request.recipient().keyHandle());
        }
        if (algorithm == PgpPublicKeyAlgorithm.X25519 || algorithm == PgpPublicKeyAlgorithm.ECDH) {
            var senderKeyAgreementKey = Objects.requireNonNull(
                    request.senderKeyAgreementKey(),
                    "senderKeyAgreementKey wird fuer schluesselaustausch-basierte Algorithmen benoetigt");
            return new HsmEcdhPublicKeyKeyEncryptionMethodGenerator(
                    recipientPgpPublicKey, keyAgreementExecutor, aesExecutor, request.recipient(),
                    senderKeyAgreementKey);
        }
        throw new IllegalArgumentException(
                "Algorithmus " + algorithm + " wird von dieser Bridge nicht fuer Verschluesselung unterstuetzt");
    }

    private void writeLiteralData(OutputStream encryptedOut, byte[] plaintext) throws IOException {
        var literalGenerator = new PGPLiteralDataGenerator();
        try (OutputStream literalOut = literalGenerator.open(
                encryptedOut, PGPLiteralData.BINARY, "", plaintext.length, PgpKeyMaterialCodec.FIXED_CREATION_TIME)) {
            literalOut.write(plaintext);
        }
    }

    @Override
    public ByteSequence decrypt(OpenPgpDecryptionRequest request) {
        try {
            var factory = new PGPObjectFactory(request.message().encoded().value(), FINGERPRINT_CALCULATOR);
            var encryptedDataList = nextOfType(factory, PGPEncryptedDataList.class, "Keine verschluesselten Daten gefunden");

            PGPPublicKeyEncryptedData encryptedData = null;
            for (var data : encryptedDataList) {
                if (data instanceof PGPPublicKeyEncryptedData candidate) {
                    encryptedData = candidate;
                    break;
                }
            }
            if (encryptedData == null) {
                throw new OpenPgpDecryptionFailedException("Kein passendes verschluesseltes Sitzungsschluessel-Paket gefunden");
            }

            var recipientAlgorithm = request.recipient().publicKey().algorithm();
            PublicKeyDataDecryptorFactory decryptorFactory = decryptorFactoryFor(recipientAlgorithm, request.recipient());

            // encryptedData.verify() liest intern denselben (internen) Stream weiter, den
            // getDataStream() zurueckgibt - der Stream darf daher vor dem verify()-Aufruf
            // NICHT geschlossen werden (siehe PGPEncryptedData#verify(): "can only be called
            // after the message has been read").
            var decryptedStream = encryptedData.getDataStream(decryptorFactory);
            var innerFactory = new PGPObjectFactory(decryptedStream, FINGERPRINT_CALCULATOR);
            var literalData = nextOfType(innerFactory, PGPLiteralData.class, "Kein Literal-Data-Paket gefunden");
            byte[] plaintext = literalData.getInputStream().readAllBytes();

            if (!encryptedData.verify()) {
                throw new OpenPgpDecryptionFailedException("Integritaetspruefung der Nutzlast fehlgeschlagen");
            }

            return ByteSequence.of(plaintext);
        } catch (OpenPgpDecryptionFailedException e) {
            throw e;
        } catch (Exception e) {
            throw new OpenPgpDecryptionFailedException("Entschluesselung fehlgeschlagen", e);
        }
    }

    private PublicKeyDataDecryptorFactory decryptorFactoryFor(PgpPublicKeyAlgorithm algorithm, PgpKeyReference recipient) {
        if (algorithm == PgpPublicKeyAlgorithm.RSA) {
            return new HsmRsaPublicKeyDataDecryptorFactory(rsaExecutor, aesExecutor, recipient.keyHandle());
        }
        if (algorithm == PgpPublicKeyAlgorithm.X25519 || algorithm == PgpPublicKeyAlgorithm.ECDH) {
            return new HsmEcdhPublicKeyDataDecryptorFactory(keyAgreementExecutor, aesExecutor, recipient);
        }
        throw new IllegalArgumentException(
                "Algorithmus " + algorithm + " wird von dieser Bridge nicht fuer Entschluesselung unterstuetzt");
    }

    @Override
    public OpenPgpMessage sign(OpenPgpSigningRequest request) {
        try {
            var signerPublicKey = request.signer().publicKey();
            int keyAlgorithmTag = PgpKeyMaterialCodec.toPacketAlgorithmTag(signerPublicKey.algorithm());
            var signerPgpPublicKey = PgpKeyMaterialCodec.toPgpPublicKey(signerPublicKey);

            var contentSignerBuilder = new HsmBackedPGPContentSignerBuilder(
                    keyAlgorithmTag, signatureExecutor, request.signer().keyHandle(), signerPgpPublicKey.getKeyID());
            var signatureGenerator = new PGPSignatureGenerator(contentSignerBuilder, signerPgpPublicKey);
            var placeholderPrivateKey = PgpKeyMaterialCodec.placeholderPrivateKey(
                    signerPgpPublicKey.getPublicKeyPacket(), signerPgpPublicKey.getKeyID());
            signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, placeholderPrivateKey);

            byte[] content = request.message().value();
            signatureGenerator.update(content);

            var outputBytes = new ByteArrayOutputStream();
            var packetOut = new BCPGOutputStream(outputBytes);
            signatureGenerator.generateOnePassVersion(true).encode(packetOut);
            writeLiteralData(packetOut, content);
            signatureGenerator.generate().encode(packetOut);
            packetOut.flush();

            return new OpenPgpMessage(ByteSequence.of(outputBytes.toByteArray()));
        } catch (PGPException | IOException e) {
            throw new OpenPgpMessageCodecException("Signieren fehlgeschlagen: " + e.getMessage(), e);
        }
    }

    @Override
    public boolean verify(OpenPgpVerificationRequest request) {
        try {
            var factory = new PGPObjectFactory(request.signedMessage().encoded().value(), FINGERPRINT_CALCULATOR);
            Object current = factory.nextObject();
            if (current instanceof PGPOnePassSignatureList) {
                current = factory.nextObject();
            }
            if (!(current instanceof PGPLiteralData literalData)) {
                throw new OpenPgpMessageCodecException("Erwartetes Literal-Data-Paket nicht gefunden", null);
            }
            byte[] content = literalData.getInputStream().readAllBytes();

            var signatureObject = factory.nextObject();
            if (!(signatureObject instanceof PGPSignatureList signatureList) || signatureList.isEmpty()) {
                throw new OpenPgpMessageCodecException("Erwartetes Signatur-Paket nicht gefunden", null);
            }
            var signature = signatureList.get(0);

            var signerPgpPublicKey = PgpKeyMaterialCodec.toPgpPublicKey(request.signerPublicKey());
            signature.init(new HsmBackedPGPContentVerifierBuilderProvider(), signerPgpPublicKey);
            signature.update(content);
            return signature.verify();
        } catch (OpenPgpMessageCodecException e) {
            throw e;
        } catch (Exception e) {
            throw new OpenPgpMessageCodecException("Verifikation fehlgeschlagen: " + e.getMessage(), e);
        }
    }

    @SuppressWarnings("unchecked")
    private static <T> T nextOfType(PGPObjectFactory factory, Class<T> type, String errorMessage) throws IOException {
        Object current = factory.nextObject();
        while (current != null && !type.isInstance(current)) {
            current = factory.nextObject();
        }
        if (current == null) {
            throw new OpenPgpMessageCodecException(errorMessage, null);
        }
        return (T) current;
    }
}
