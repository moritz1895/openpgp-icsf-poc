package ms.rohde.openpgpicsfpoc.adapters.outbound.openpgp.bc;

import jakarta.inject.Inject;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Constructor;
import java.util.Arrays;
import java.util.Objects;
import ms.rohde.hexagonalarch.annotations.InfrastructureServiceAdapter;
import ms.rohde.openpgpicsfpoc.core.domain.ByteSequence;
import ms.rohde.openpgpicsfpoc.core.domain.OpenPgpMessage;
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
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmKeyEncapsulationExecutor;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmRsaEncryptionExecutor;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmSignatureExecutor;
import org.bouncycastle.bcpg.AEADAlgorithmTags;
import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.InputStreamPacket;
import org.bouncycastle.bcpg.Packet;
import org.bouncycastle.bcpg.PacketTags;
import org.bouncycastle.bcpg.PublicKeyEncSessionPacket;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPSessionKeyEncryptedData;
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
 * Orchestrierung genutzt ({@link PGPEncryptedDataGenerator},
 * {@link PGPSignatureGenerator}, {@link PGPObjectFactory}, ...) - jede
 * tatsaechliche kryptographische Operation laeuft ueber die injizierten
 * Hsm-Executor-Ports (siehe Projektplan, Abschnitt "Kernidee der technischen
 * Loesung").
 *
 * <p><b>Scope dieser Iteration:</b> RSA, ECC (natives X25519/Ed25519 nach RFC 9580 und
 * das klassische ECDH/ECDSA-Fallback-Profil nach RFC 6637) sowie die
 * Post-Quantum-Komposit-Verschluesselung ML-KEM-768+X25519 nach RFC 9980 - die PQC-Signatur
 * ML-DSA-65+Ed25519 erfordert v6-Schluessel/-Signaturen und bleibt ausserhalb des Scopes
 * (siehe Aufgabenstellung).</p>
 *
 * <p><b>Entschluesselungs-Sonderfall Algorithmus-ID 35:</b> {@code bcpg-jdk18on} 1.85 kennt
 * diese Algorithmus-ID nicht - sowohl der lesende Konstruktor von
 * {@link org.bouncycastle.bcpg.PublicKeyEncSessionPacket} als auch die interne
 * Paketgruppierung von {@link PGPEncryptedDataList} brechen beim Antreffen eines
 * entsprechenden PKESK-Pakets mit einer {@code IOException} ab, noch bevor eigener Code
 * eingreifen koennte - {@link #decrypt(OpenPgpDecryptionRequest)} kann fuer diesen
 * Algorithmus daher nicht wie fuer alle anderen den generischen {@code PGPObjectFactory}-Pfad
 * nehmen. Stattdessen parst {@link #decryptComposite(OpenPgpDecryptionRequest)} das
 * PKESK-Paket manuell (reine Paket-Framing-Logik, siehe {@link HsmCompositeMlKemPkeskCodec})
 * und erzeugt das fuer die eigentliche SEIPD-Entschluesselung/-Integritaetspruefung
 * benoetigte {@link PGPSessionKeyEncryptedData} ueber dessen paketsichtbaren Konstruktor
 * per Reflection (siehe {@link #newSessionKeyEncryptedData(InputStreamPacket)}) - so bleibt
 * die (nicht triviale) MDC-/AEAD-Verifikationslogik vollstaendig in Bouncy Castle statt in
 * dieser Bridge dupliziert zu werden. Die Reflection funktioniert ohne
 * {@code --add-opens}, weil sowohl der gepackte Spring-Boot-Jar (`java -jar`) als auch die
 * Maven-Surefire-Testausfuehrung {@code bcpg-jdk18on} auf dem Classpath (unbenanntes Modul)
 * statt auf dem Modulpfad laden - siehe {@code module-info.java} dieses Projekts.</p>
 */
@InfrastructureServiceAdapter
public final class HsmBackedOpenPgpMessageCodec implements OpenPgpMessageCodec {

    private static final int AEAD_CHUNK_SIZE_EXPONENT = 12; // 4096-Byte-Chunks

    private final HsmRsaEncryptionExecutor rsaExecutor;
    private final HsmAesEncryptionExecutor aesExecutor;
    private final HsmKeyAgreementExecutor keyAgreementExecutor;
    private final HsmKeyEncapsulationExecutor keyEncapsulationExecutor;
    private final HsmSignatureExecutor signatureExecutor;
    private final BcKeyFingerprintCalculator fingerprintCalculator;

    @Inject
    public HsmBackedOpenPgpMessageCodec(
            HsmRsaEncryptionExecutor rsaExecutor,
            HsmAesEncryptionExecutor aesExecutor,
            HsmKeyAgreementExecutor keyAgreementExecutor,
            HsmKeyEncapsulationExecutor keyEncapsulationExecutor,
            HsmSignatureExecutor signatureExecutor,
            BcKeyFingerprintCalculator fingerprintCalculator) {
        this.rsaExecutor = Objects.requireNonNull(rsaExecutor, "rsaExecutor darf nicht null sein");
        this.aesExecutor = Objects.requireNonNull(aesExecutor, "aesExecutor darf nicht null sein");
        this.keyAgreementExecutor = Objects.requireNonNull(keyAgreementExecutor, "keyAgreementExecutor darf nicht null sein");
        this.keyEncapsulationExecutor =
                Objects.requireNonNull(keyEncapsulationExecutor, "keyEncapsulationExecutor darf nicht null sein");
        this.signatureExecutor = Objects.requireNonNull(signatureExecutor, "signatureExecutor darf nicht null sein");
        this.fingerprintCalculator = Objects.requireNonNull(fingerprintCalculator, "fingerprintCalculator darf nicht null sein");
    }

    @Override
    public OpenPgpMessage encrypt(OpenPgpEncryptionRequest request) {
        try {
            PgpPublicKey recipientPublicKey = request.recipient().publicKey();
            PGPPublicKey recipientPgpPublicKey = PgpKeyMaterialCodec.toPgpPublicKey(recipientPublicKey, fingerprintCalculator);

            HsmBackedPGPDataEncryptorBuilder dataEncryptorBuilder =
                    new HsmBackedPGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256, aesExecutor);
            dataEncryptorBuilder.setWithAEAD(AEADAlgorithmTags.GCM, AEAD_CHUNK_SIZE_EXPONENT);
            dataEncryptorBuilder.setUseV6AEAD();

            PGPEncryptedDataGenerator generator = new PGPEncryptedDataGenerator(dataEncryptorBuilder);
            generator.addMethod(methodGeneratorFor(recipientPublicKey, recipientPgpPublicKey, request));

            byte[] plaintext = request.plaintext().value();
            ByteArrayOutputStream outputBytes = new ByteArrayOutputStream();
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
            PgpPublicKey recipientPublicKey, PGPPublicKey recipientPgpPublicKey, OpenPgpEncryptionRequest request) {
        PgpPublicKeyAlgorithm algorithm = recipientPublicKey.algorithm();
        if (algorithm == PgpPublicKeyAlgorithm.RSA) {
            return new HsmRsaPublicKeyKeyEncryptionMethodGenerator(
                    recipientPgpPublicKey, rsaExecutor, request.recipient().keyHandle());
        }
        if (algorithm == PgpPublicKeyAlgorithm.X25519 || algorithm == PgpPublicKeyAlgorithm.ECDH) {
            PgpKeyReference senderKeyAgreementKey = Objects.requireNonNull(
                    request.senderKeyAgreementKey(),
                    "senderKeyAgreementKey wird fuer schluesselaustausch-basierte Algorithmen benoetigt");
            return new HsmEcdhPublicKeyKeyEncryptionMethodGenerator(
                    recipientPgpPublicKey, keyAgreementExecutor, aesExecutor, request.recipient(),
                    senderKeyAgreementKey);
        }
        if (algorithm == PgpPublicKeyAlgorithm.ML_KEM_768_X25519) {
            PgpKeyReference senderKeyAgreementKey = Objects.requireNonNull(
                    request.senderKeyAgreementKey(),
                    "senderKeyAgreementKey wird fuer schluesselaustausch-basierte Algorithmen benoetigt");
            return new HsmCompositeMlKemKeyEncryptionMethodGenerator(
                    recipientPgpPublicKey, keyAgreementExecutor, keyEncapsulationExecutor, aesExecutor,
                    request.recipient(), senderKeyAgreementKey);
        }
        throw new IllegalArgumentException(
                "Algorithmus " + algorithm + " wird von dieser Bridge nicht fuer Verschluesselung unterstuetzt");
    }

    private void writeLiteralData(OutputStream encryptedOut, byte[] plaintext) throws IOException {
        PGPLiteralDataGenerator literalGenerator = new PGPLiteralDataGenerator();
        try (OutputStream literalOut = literalGenerator.open(
                encryptedOut, PGPLiteralData.BINARY, "", plaintext.length, PgpKeyMaterialCodec.FIXED_CREATION_TIME)) {
            literalOut.write(plaintext);
        }
    }

    @Override
    public ByteSequence decrypt(OpenPgpDecryptionRequest request) {
        if (request.recipient().publicKey().algorithm() == PgpPublicKeyAlgorithm.ML_KEM_768_X25519) {
            return decryptComposite(request);
        }
        try {
            PGPObjectFactory factory = new PGPObjectFactory(request.message().encoded().value(), fingerprintCalculator);
            PGPEncryptedDataList encryptedDataList =
                    nextOfType(factory, PGPEncryptedDataList.class, "Keine verschluesselten Daten gefunden");

            PGPPublicKeyEncryptedData encryptedData = null;
            for (PGPEncryptedData data : encryptedDataList) {
                if (data instanceof PGPPublicKeyEncryptedData candidate) {
                    encryptedData = candidate;
                    break;
                }
            }
            if (encryptedData == null) {
                throw new OpenPgpDecryptionFailedException("Kein passendes verschluesseltes Sitzungsschluessel-Paket gefunden");
            }

            PgpPublicKeyAlgorithm recipientAlgorithm = request.recipient().publicKey().algorithm();
            PublicKeyDataDecryptorFactory decryptorFactory = decryptorFactoryFor(recipientAlgorithm, request.recipient());

            // encryptedData.verify() liest intern denselben (internen) Stream weiter, den
            // getDataStream() zurueckgibt - der Stream darf daher vor dem verify()-Aufruf
            // NICHT geschlossen werden (siehe PGPEncryptedData#verify(): "can only be called
            // after the message has been read").
            InputStream decryptedStream = encryptedData.getDataStream(decryptorFactory);
            PGPObjectFactory innerFactory = new PGPObjectFactory(decryptedStream, fingerprintCalculator);
            PGPLiteralData literalData = nextOfType(innerFactory, PGPLiteralData.class, "Kein Literal-Data-Paket gefunden");
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
            return new HsmEcdhPublicKeyDataDecryptorFactory(keyAgreementExecutor, aesExecutor, recipient, fingerprintCalculator);
        }
        throw new IllegalArgumentException(
                "Algorithmus " + algorithm + " wird von dieser Bridge nicht fuer Entschluesselung unterstuetzt");
    }

    /**
     * Entschluesselungspfad fuer das komposite ML-KEM-768+X25519-Verfahren (Algorithmus-ID
     * 35) - siehe Klassen-JavaDoc, Abschnitt "Entschluesselungs-Sonderfall Algorithmus-ID
     * 35", fuer die Begruendung, warum dieser Pfad nicht ueber {@code PGPObjectFactory}
     * laufen kann.
     */
    private ByteSequence decryptComposite(OpenPgpDecryptionRequest request) {
        try {
            byte[] message = request.message().encoded().value();
            HsmCompositeMlKemPkeskCodec.RawPacket leadingPacket = HsmCompositeMlKemPkeskCodec.readPacketHeader(message, 0);
            if (leadingPacket.tag() != PacketTags.PUBLIC_KEY_ENC_SESSION) {
                throw new OpenPgpDecryptionFailedException(
                        "Erwartetes PKESK-Paket nicht gefunden (Paket-Tag " + leadingPacket.tag() + ")");
            }
            HsmCompositeMlKemPkeskCodec.ParsedPkeskHeader pkeskHeader =
                    HsmCompositeMlKemPkeskCodec.parsePkeskBody(leadingPacket.body());
            if (pkeskHeader.algorithm() != PgpKeyMaterialCodec.COMPOSITE_ML_KEM_768_X25519_ALGORITHM_TAG) {
                throw new OpenPgpDecryptionFailedException(
                        "PKESK-Algorithmus " + pkeskHeader.algorithm() + " passt nicht zum erwarteten"
                                + " Komposit-Algorithmus " + PgpKeyMaterialCodec.COMPOSITE_ML_KEM_768_X25519_ALGORITHM_TAG);
            }
            boolean isV3 = pkeskHeader.version() == PublicKeyEncSessionPacket.VERSION_3;
            HsmCompositeMlKemPkeskCodec.DecodedAlgorithmSpecificData algorithmSpecificData =
                    HsmCompositeMlKemPkeskCodec.decodeAlgorithmSpecificData(pkeskHeader.algorithmSpecificData(), isV3);

            HsmCompositeMlKemPublicKeyDataDecryptorFactory decryptorFactory = new HsmCompositeMlKemPublicKeyDataDecryptorFactory(
                    keyAgreementExecutor, keyEncapsulationExecutor, aesExecutor, request.recipient(),
                    algorithmSpecificData, isV3);

            byte[] remainder = Arrays.copyOfRange(message, leadingPacket.totalLength(), message.length);
            BCPGInputStream seipdIn = new BCPGInputStream(new ByteArrayInputStream(remainder));
            Packet seipdPacket = seipdIn.readPacket();
            if (!(seipdPacket instanceof InputStreamPacket seipdInputStreamPacket)) {
                throw new OpenPgpDecryptionFailedException(
                        "Erwartetes SEIPD-Paket nicht gefunden (Paket-Tag " + seipdPacket.getPacketTag() + ")");
            }

            PGPSessionKeyEncryptedData encryptedData = newSessionKeyEncryptedData(seipdInputStreamPacket);
            // encryptedData.verify() liest intern denselben (internen) Stream weiter, den
            // getDataStream() zurueckgibt - siehe gleichlautender Hinweis in decrypt() oben.
            InputStream decryptedStream = encryptedData.getDataStream(decryptorFactory);
            PGPObjectFactory innerFactory = new PGPObjectFactory(decryptedStream, fingerprintCalculator);
            PGPLiteralData literalData = nextOfType(innerFactory, PGPLiteralData.class, "Kein Literal-Data-Paket gefunden");
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

    /**
     * Erzeugt ein {@link PGPSessionKeyEncryptedData} ueber dessen paketsichtbaren (in
     * {@code org.bouncycastle.openpgp}) Konstruktor per Reflection - der einzige oeffentliche
     * Konstruktionsweg fuer dieses BC-Objekt fuehrt sonst ausschliesslich ueber
     * {@link PGPEncryptedDataList}, das fuer Algorithmus-ID 35 nicht verwendet werden kann
     * (siehe Klassen-JavaDoc). {@link PGPSessionKeyEncryptedData} ist BCs Gegenstueck zu
     * {@code gpg --override-session-key}: es kapselt exakt die SEIPD-v2/AEAD-Entschluesselungs-
     * und Chunk-Verifikationslogik, die alle anderen Algorithmen dieser Bridge bereits ueber
     * {@link PGPPublicKeyEncryptedData} wiederverwenden.
     */
    private static PGPSessionKeyEncryptedData newSessionKeyEncryptedData(InputStreamPacket seipdPacket) {
        try {
            Constructor<PGPSessionKeyEncryptedData> constructor =
                    PGPSessionKeyEncryptedData.class.getDeclaredConstructor(InputStreamPacket.class);
            constructor.setAccessible(true);
            return constructor.newInstance(seipdPacket);
        } catch (ReflectiveOperationException e) {
            throw new OpenPgpDecryptionFailedException(
                    "PGPSessionKeyEncryptedData konnte nicht reflektiv erzeugt werden - siehe Klassen-JavaDoc von "
                            + HsmBackedOpenPgpMessageCodec.class.getSimpleName() + " zur Hintergrund-Begruendung",
                    e);
        }
    }

    @Override
    public OpenPgpMessage sign(OpenPgpSigningRequest request) {
        try {
            PgpPublicKey signerPublicKey = request.signer().publicKey();
            int keyAlgorithmTag = PgpKeyMaterialCodec.toPacketAlgorithmTag(signerPublicKey.algorithm());
            PGPPublicKey signerPgpPublicKey = PgpKeyMaterialCodec.toPgpPublicKey(signerPublicKey, fingerprintCalculator);

            HsmBackedPGPContentSignerBuilder contentSignerBuilder = new HsmBackedPGPContentSignerBuilder(
                    keyAlgorithmTag, signatureExecutor, request.signer().keyHandle(), signerPgpPublicKey.getKeyID());
            PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(contentSignerBuilder, signerPgpPublicKey);
            PGPPrivateKey placeholderPrivateKey = PgpKeyMaterialCodec.placeholderPrivateKey(
                    signerPgpPublicKey.getPublicKeyPacket(), signerPgpPublicKey.getKeyID());
            signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, placeholderPrivateKey);

            byte[] content = request.message().value();
            signatureGenerator.update(content);

            ByteArrayOutputStream outputBytes = new ByteArrayOutputStream();
            BCPGOutputStream packetOut = new BCPGOutputStream(outputBytes);
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
            PGPObjectFactory factory = new PGPObjectFactory(request.signedMessage().encoded().value(), fingerprintCalculator);
            Object current = factory.nextObject();
            if (current instanceof PGPOnePassSignatureList) {
                current = factory.nextObject();
            }
            if (!(current instanceof PGPLiteralData literalData)) {
                throw new OpenPgpMessageCodecException("Erwartetes Literal-Data-Paket nicht gefunden", null);
            }
            byte[] content = literalData.getInputStream().readAllBytes();

            Object signatureObject = factory.nextObject();
            if (!(signatureObject instanceof PGPSignatureList signatureList) || signatureList.isEmpty()) {
                throw new OpenPgpMessageCodecException("Erwartetes Signatur-Paket nicht gefunden", null);
            }
            PGPSignature signature = signatureList.get(0);

            PGPPublicKey signerPgpPublicKey = PgpKeyMaterialCodec.toPgpPublicKey(request.signerPublicKey(), fingerprintCalculator);
            signature.init(new HsmBackedPGPContentVerifierBuilderProvider(), signerPgpPublicKey);
            signature.update(content);
            return signature.verify();
        } catch (OpenPgpMessageCodecException e) {
            throw e;
        } catch (Exception e) {
            throw new OpenPgpMessageCodecException("Verifikation fehlgeschlagen: " + e.getMessage(), e);
        }
    }

    /**
     * {@code type.isInstance(current)} wird bereits zur Laufzeit gegen {@code current}
     * geprueft, bevor der Cast erfolgt - der Compiler kann diese Typsicherheit aber nicht
     * aus dem generischen Parameter {@code Class<T>} ableiten (Erasure: {@code T} ist zur
     * Laufzeit nicht bekannt), daher ist die Unterdrueckung hier sicher, aber unvermeidbar.
     */
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
