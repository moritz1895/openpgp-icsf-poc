package ms.rohde.openpgpicsfpoc.adapters.inbound.cli;

import jakarta.inject.Inject;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import ms.rohde.hexagonalarch.annotations.DrivingAdapter;
import ms.rohde.openpgpicsfpoc.adapters.outbound.hsm.dummy.InMemoryHsmKeyStore;
import ms.rohde.openpgpicsfpoc.adapters.outbound.openpgp.bc.EphemeralPeerKeyHandles;
import ms.rohde.openpgpicsfpoc.core.app.DecryptOpenPgpMessageCommand;
import ms.rohde.openpgpicsfpoc.core.app.EncryptOpenPgpMessageCommand;
import ms.rohde.openpgpicsfpoc.core.app.SignOpenPgpMessageCommand;
import ms.rohde.openpgpicsfpoc.core.app.VerifyOpenPgpSignatureCommand;
import ms.rohde.openpgpicsfpoc.core.domain.ByteSequence;
import ms.rohde.openpgpicsfpoc.core.domain.HsmKeyHandle;
import ms.rohde.openpgpicsfpoc.core.domain.OpenPgpMessage;
import ms.rohde.openpgpicsfpoc.core.domain.PgpEllipticCurve;
import ms.rohde.openpgpicsfpoc.core.domain.PgpEncryptionProfile;
import ms.rohde.openpgpicsfpoc.core.domain.PgpKeyReference;
import ms.rohde.openpgpicsfpoc.core.domain.PgpPublicKey;
import ms.rohde.openpgpicsfpoc.ports.inbound.DecryptOpenPgpMessageUseCase;
import ms.rohde.openpgpicsfpoc.ports.inbound.EncryptOpenPgpMessageUseCase;
import ms.rohde.openpgpicsfpoc.ports.inbound.SignOpenPgpMessageUseCase;
import ms.rohde.openpgpicsfpoc.ports.inbound.VerifyOpenPgpSignatureUseCase;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jspecify.annotations.Nullable;
import org.springframework.boot.CommandLineRunner;

/**
 * Treibender CLI-Demo-Adapter: durchlaeuft beim Anwendungsstart einmalig alle in dieser
 * PoC-Iteration unterstuetzten Algorithmus-/Profil-Kombinationen (RSA, natives X25519, klassisches
 * ECDH/ECDSA-Fallback ueber P-256 - Post-Quantum ist noch nicht implementiert) end-to-end ueber die
 * treibenden Ports dieses Projekts und beendet sich danach - kein Dauerbetrieb, kein HTTP-Port.
 *
 * <p>Da diese PoC keinen Hsm-Keygen-Port kennt (Schluessel gelten als vorab im HSM vorhanden, siehe
 * Projektplan), erzeugt dieser Adapter frische Demo-Schluesselpaare lokal ({@link DemoKeyMaterial})
 * und registriert sie ueber {@link InMemoryHsmKeyStore} als bereits im (simulierten) HSM vorhanden -
 * exakt das Vorgehen, das die Integrationstests der Bouncy-Castle-Bridge (siehe
 * {@code adapters.outbound.openpgp.bc}, Testquelle) fuer denselben Zweck verwenden.</p>
 *
 * <p>Fuer jede Verschluesselungs-Empfaenger-Algorithmus-Kombination wird sowohl das klassische
 * Container-Profil ({@link PgpEncryptionProfile#LEGACY_CFB_MDC}) als auch das moderne
 * ({@link PgpEncryptionProfile#AEAD_V2}) einmal komplett verschluesselt und wieder entschluesselt;
 * fuer jeden Signaturalgorithmus wird einmal signiert und wieder verifiziert. Jeder Durchlauf wird
 * einzeln geloggt, am Ende folgt eine Gesamtzusammenfassung.</p>
 */
@DrivingAdapter
public final class OpenPgpDemoRunner implements CommandLineRunner {

    private static final Logger LOG = LogManager.getLogger(OpenPgpDemoRunner.class);

    /** Paketsichtbar statt privat, damit Tests denselben Wert referenzieren koennen. */
    static final ByteSequence DEMO_PLAINTEXT =
            ByteSequence.of("Hallo, HSM-gestuetztes OpenPGP!".getBytes(StandardCharsets.UTF_8));

    private final EncryptOpenPgpMessageUseCase encryptUseCase;
    private final DecryptOpenPgpMessageUseCase decryptUseCase;
    private final SignOpenPgpMessageUseCase signUseCase;
    private final VerifyOpenPgpSignatureUseCase verifyUseCase;
    private final InMemoryHsmKeyStore keyStore;

    @Inject
    public OpenPgpDemoRunner(
            EncryptOpenPgpMessageUseCase encryptUseCase,
            DecryptOpenPgpMessageUseCase decryptUseCase,
            SignOpenPgpMessageUseCase signUseCase,
            VerifyOpenPgpSignatureUseCase verifyUseCase,
            InMemoryHsmKeyStore keyStore) {
        this.encryptUseCase = Objects.requireNonNull(encryptUseCase, "encryptUseCase darf nicht null sein");
        this.decryptUseCase = Objects.requireNonNull(decryptUseCase, "decryptUseCase darf nicht null sein");
        this.signUseCase = Objects.requireNonNull(signUseCase, "signUseCase darf nicht null sein");
        this.verifyUseCase = Objects.requireNonNull(verifyUseCase, "verifyUseCase darf nicht null sein");
        this.keyStore = Objects.requireNonNull(keyStore, "keyStore darf nicht null sein");
    }

    @Override
    public void run(String... args) {
        LOG.info("Starte OpenPGP-HSM-Demo (RSA, natives X25519, klassisches ECDH/ECDSA-Fallback ueber P-256)...");

        List<DemoOutcome> outcomes = new ArrayList<>();
        for (DemoRecipient recipient : provisionEncryptionRecipients()) {
            for (PgpEncryptionProfile profile : PgpEncryptionProfile.values()) {
                outcomes.add(runEncryptionRoundTrip(recipient, profile));
            }
        }
        for (LabeledKeyReference signer : provisionSigners()) {
            outcomes.add(runSigningRoundTrip(signer));
        }

        logSummary(outcomes);

        if (outcomes.stream().anyMatch(outcome -> !outcome.success())) {
            throw new IllegalStateException(
                    "Mindestens ein Demo-Durchlauf ist fehlgeschlagen - siehe Log-Ausgabe oben");
        }
    }

    private List<DemoRecipient> provisionEncryptionRecipients() {
        try {
            List<DemoRecipient> recipients = new ArrayList<>();

            KeyPair rsaKeyPair = DemoKeyMaterial.generateRsa();
            recipients.add(new DemoRecipient(
                    "RSA",
                    register("demo-rsa-recipient", rsaKeyPair, DemoKeyMaterial.rsaPublicKey(rsaKeyPair)),
                    null));

            KeyPair x25519RecipientKeyPair = DemoKeyMaterial.generateX25519();
            PgpKeyReference x25519Recipient = register(
                    "demo-x25519-recipient",
                    x25519RecipientKeyPair,
                    DemoKeyMaterial.x25519PublicKey(x25519RecipientKeyPair));
            KeyPair x25519SenderKeyPair = DemoKeyMaterial.generateX25519();
            PgpKeyReference x25519Sender = registerSenderKeyAgreementKey(
                    "demo-x25519-sender", x25519SenderKeyPair, DemoKeyMaterial.x25519PublicKey(x25519SenderKeyPair));
            recipients.add(new DemoRecipient("X25519 (nativ, RFC 9580)", x25519Recipient, x25519Sender));

            KeyPair ecdhRecipientKeyPair = DemoKeyMaterial.generateEc(PgpEllipticCurve.P256);
            PgpKeyReference ecdhRecipient = register(
                    "demo-ecdh-p256-recipient",
                    ecdhRecipientKeyPair,
                    DemoKeyMaterial.ecdhPublicKey(ecdhRecipientKeyPair, PgpEllipticCurve.P256));
            KeyPair ecdhSenderKeyPair = DemoKeyMaterial.generateEc(PgpEllipticCurve.P256);
            PgpKeyReference ecdhSender = registerSenderKeyAgreementKey(
                    "demo-ecdh-p256-sender",
                    ecdhSenderKeyPair,
                    DemoKeyMaterial.ecdhPublicKey(ecdhSenderKeyPair, PgpEllipticCurve.P256));
            recipients.add(
                    new DemoRecipient("ECDH P-256 (klassisches Fallback-Profil, RFC 6637)", ecdhRecipient, ecdhSender));

            return recipients;
        } catch (GeneralSecurityException e) {
            throw new DemoKeyProvisioningException("Demo-Empfaengerschluessel konnten nicht erzeugt werden", e);
        }
    }

    private List<LabeledKeyReference> provisionSigners() {
        try {
            List<LabeledKeyReference> signers = new ArrayList<>();

            KeyPair rsaKeyPair = DemoKeyMaterial.generateRsa();
            signers.add(new LabeledKeyReference(
                    "RSA", register("demo-rsa-signer", rsaKeyPair, DemoKeyMaterial.rsaPublicKey(rsaKeyPair))));

            KeyPair ecdsaKeyPair = DemoKeyMaterial.generateEc(PgpEllipticCurve.P256);
            signers.add(new LabeledKeyReference(
                    "ECDSA P-256",
                    register(
                            "demo-ecdsa-signer",
                            ecdsaKeyPair,
                            DemoKeyMaterial.ecdsaPublicKey(ecdsaKeyPair, PgpEllipticCurve.P256))));

            KeyPair eddsaKeyPair = DemoKeyMaterial.generateEd25519();
            signers.add(new LabeledKeyReference(
                    "EdDSA Ed25519",
                    register("demo-eddsa-signer", eddsaKeyPair, DemoKeyMaterial.eddsaPublicKey(eddsaKeyPair))));

            return signers;
        } catch (GeneralSecurityException e) {
            throw new DemoKeyProvisioningException("Demo-Signaturschluessel konnten nicht erzeugt werden", e);
        }
    }

    private PgpKeyReference register(String alias, KeyPair keyPair, PgpPublicKey publicKey) {
        var handle = new HsmKeyHandle(alias);
        keyStore.registerKeyPair(handle, keyPair);
        return new PgpKeyReference(handle, publicKey);
    }

    /**
     * Registriert einen Sender-Schluessel fuer schluesselaustausch-basierte Verschluesselung -
     * sowohl unter seinem eigentlichen Alias als auch unter dem inhaltsadressierten Handle, den
     * {@link EphemeralPeerKeyHandles} beim Entschluesseln aus dem im Paket eingebetteten Punkt
     * ableitet (siehe dortiges JavaDoc zur zugrunde liegenden PoC-Einschraenkung).
     */
    private PgpKeyReference registerSenderKeyAgreementKey(String alias, KeyPair keyPair, PgpPublicKey publicKey) {
        PgpKeyReference reference = register(alias, keyPair, publicKey);
        HsmKeyHandle derivedHandle = EphemeralPeerKeyHandles.deriveFrom(publicKey.encodedKeyMaterial().value());
        keyStore.registerPublicKey(derivedHandle, keyPair.getPublic());
        return reference;
    }

    private DemoOutcome runEncryptionRoundTrip(DemoRecipient recipient, PgpEncryptionProfile profile) {
        String label = "Verschluesseln/Entschluesseln " + recipient.label() + " / " + profile;
        try {
            var encryptCommand = new EncryptOpenPgpMessageCommand(
                    DEMO_PLAINTEXT, recipient.recipient(), recipient.senderKeyAgreementKey(), profile);
            OpenPgpMessage encrypted = encryptUseCase.encrypt(encryptCommand);

            var decryptCommand = new DecryptOpenPgpMessageCommand(encrypted, recipient.recipient());
            ByteSequence decrypted = decryptUseCase.decrypt(decryptCommand);

            if (decrypted.equals(DEMO_PLAINTEXT)) {
                LOG.info("[OK]      {}: entschluesselter Klartext stimmt mit dem Original ueberein", label);
                return new DemoOutcome(label, true);
            }
            LOG.error("[FEHLER]  {}: entschluesselter Klartext weicht vom Original ab", label);
            return new DemoOutcome(label, false);
        } catch (RuntimeException e) {
            LOG.error("[FEHLER]  {}: {}", label, e.getMessage(), e);
            return new DemoOutcome(label, false);
        }
    }

    private DemoOutcome runSigningRoundTrip(LabeledKeyReference signer) {
        String label = "Signieren/Verifizieren " + signer.label();
        try {
            var signCommand = new SignOpenPgpMessageCommand(DEMO_PLAINTEXT, signer.reference());
            OpenPgpMessage signed = signUseCase.sign(signCommand);

            var verifyCommand = new VerifyOpenPgpSignatureCommand(signed, signer.reference().publicKey());
            boolean valid = verifyUseCase.verify(verifyCommand);

            if (valid) {
                LOG.info("[OK]      {}: Signatur erfolgreich verifiziert", label);
                return new DemoOutcome(label, true);
            }
            LOG.error("[FEHLER]  {}: Signaturverifikation ergab 'ungueltig'", label);
            return new DemoOutcome(label, false);
        } catch (RuntimeException e) {
            LOG.error("[FEHLER]  {}: {}", label, e.getMessage(), e);
            return new DemoOutcome(label, false);
        }
    }

    private void logSummary(List<DemoOutcome> outcomes) {
        long successCount = outcomes.stream().filter(DemoOutcome::success).count();
        LOG.info(
                "===== Zusammenfassung OpenPGP-HSM-Demo ({} von {} Durchlaeufen erfolgreich) =====",
                successCount,
                outcomes.size());
        for (DemoOutcome outcome : outcomes) {
            LOG.info("{}  {}", outcome.success() ? "[OK]     " : "[FEHLER] ", outcome.label());
        }
    }

    private record DemoOutcome(String label, boolean success) {}

    private record DemoRecipient(
            String label, PgpKeyReference recipient, @Nullable PgpKeyReference senderKeyAgreementKey) {}

    private record LabeledKeyReference(String label, PgpKeyReference reference) {}
}
