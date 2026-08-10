# Die Bouncy-Castle-HSM-Bridge

Dieses Dokument erklärt, wie `adapters/outbound/openpgp/bc` die OpenPGP-Paketlogik von
Bouncy Castle mit den proprietären Hsm-Primitives dieses Projekts verbindet — ohne dass
Bouncy Castle irgendwo eine echte kryptographische Operation mit geheimem Schlüsselmaterial
ausführt. Zielgruppe: ein Entwickler, der den Code noch nicht kennt und verstehen will, wie
der Mechanismus funktioniert, ohne alle ~20 Klassen im Detail zu lesen.

Hintergrund und Scope-Entscheidungen (SEIPD-Profile, ECC/PQC-Auswahl, CCA-Realitätscheck)
stehen in `docs/features/openpgp-encryption.md` und `docs/features/openpgp-signing.md`.
Dieses Dokument beschreibt ausschließlich die technische Umsetzung im Adapter-Paket.

## 1. Grundprinzip: Bouncy Castle nur für Paketformat, nie für Kryptographie

Bouncy Castles `org.bouncycastle.openpgp`-API ist bewusst provider-agnostisch aufgebaut. Die
Referenzimplementierungen (`Bc*`, `Jce*`) sind nur *eine* mögliche Implementierung einer Reihe
von SPI-Interfaces (Service Provider Interfaces). Diese Bridge implementiert dieselben
Interfaces neu — gegen die Hsm-Executor-Ports statt gegen einen JCE-Provider oder BCs eigene
Lightweight-Crypto-Klassen.

Von Bouncy Castle genutzt wird ausschließlich:

- **Paket-Serialisierung/-Parsing**: `PGPObjectFactory`, `BCPGOutputStream`, MPI-Kodierung,
  Radix64/Armor, PKESK-/SEIPD-/Signaturpaket-Struktur.
- **Orchestrierung**: `PGPEncryptedDataGenerator`, `PGPSignatureGenerator`,
  `PGPLiteralDataGenerator`.
- **Schlüsselmodell auf Paketebene**: `PGPPublicKey`, `PublicKeyPacket`, `BCPGKey`-Subtypen
  (`RSAPublicBCPGKey`, `ECDHPublicBCPGKey`, `X25519PublicBCPGKey`, …) — reine Datencontainer,
  keine Kryptografunktionen.

Folgende SPI-Extension-Points implementiert die Bridge selbst, jeweils gegen einen
Hsm-Executor-Port:

| BC-Extension-Point | Bridge-Implementierung | Ersetzt normalerweise |
|---|---|---|
| `PGPKeyEncryptionMethodGenerator` | `HsmRsaPublicKeyKeyEncryptionMethodGenerator`, `HsmEcdhPublicKeyKeyEncryptionMethodGenerator` | `JcePublicKeyKeyEncryptionMethodGenerator` |
| `PublicKeyDataDecryptorFactory` (via `AbstractPublicKeyDataDecryptorFactory`) | `HsmRsaPublicKeyDataDecryptorFactory`, `HsmEcdhPublicKeyDataDecryptorFactory` | `JcePublicKeyDataDecryptorFactory` |
| `PGPDataEncryptorBuilder` | `HsmBackedPGPDataEncryptorBuilder` | `JcePGPDataEncryptorBuilder` / `BcPGPDataEncryptorBuilder` |
| `PGPContentSignerBuilder` | `HsmBackedPGPContentSignerBuilder` | `JcaPGPContentSignerBuilder` |
| `PGPContentVerifierBuilderProvider` | `HsmBackedPGPContentVerifierBuilderProvider` | `JcaPGPContentVerifierBuilderProvider` (für RSA/ECDSA tatsächlich unverändert weiterverwendet, siehe Abschnitt 5) |

Das funktioniert, weil BC diese Interfaces genau so schneidet, dass "wie wird kryptographisch
operiert" und "wie sieht das Paket aus" sauber getrennt sind — exakt die Trennung, die dieses
Projekt braucht, um private Schlüsseloperationen an eine HSM-Primitive statt an einen
JCE-Provider zu delegieren.

Einstiegspunkt ist `HsmBackedOpenPgpMessageCodec` (implementiert `OpenPgpMessageCodec`), das
für `encrypt`/`decrypt`/`sign`/`verify` die jeweils passenden Bridge-Klassen zusammensteckt und
an die BC-Orchestrierungsklassen übergibt.

## 2. Die fünf Hsm-Executor-Ports und das Builder→Request→Executor-Muster

Alle fünf Ports unter `ports/outbound/hsm/` folgen demselben dreiteiligen Muster:

1. **Builder-Interface** (z. B. `HsmAesEncryption`, `HsmRsaEncryption`, `HsmSignature`,
   `HsmKeyAgreement`, `HsmKeyEncapsulation`) — fluente Zusammenbau-Logik ohne
   Infrastruktur-Bezug, mit statischer `builder()`-Fabrikmethode und einer inneren
   `Default`-Implementierung. Modelliert die reale proprietäre Hsm-Primitives-API (Builder
   erzeugt Ausführungsobjekt, siehe Projektkontext).
2. **Request-Record** (z. B. `HsmAesEncryptionRequest`) — unveränderliches Ausführungsobjekt,
   validiert im kompakten Konstruktor (z. B. "ECB nur mit genau 16 Byte Input", "GCM-Decrypt
   braucht `authenticationTag`").
3. **Executor-Interface** (z. B. `HsmAesEncryptionExecutor`, annotiert
   `@InfrastructureServicePort`) — der eigentliche Outbound-Port mit einer einzigen
   `execute(Request)`-Methode. Nur dieses Interface wird von einem Adapter implementiert
   (produktiv: ICSF-Adapter, in dieser PoC: `adapters/outbound/hsm/dummy`).

Typischer Aufruf aus einer Bridge-Klasse (`HsmCfbEngine`):

```java
var request = HsmAesEncryption.builder()
        .sessionKey(ByteSequence.of(sessionKey))
        .cipherMode(HsmAesCipherMode.ECB)
        .operation(HsmCipherOperation.ENCRYPT)
        .input(ByteSequence.of(block))
        .build();
return executor.execute(request).output().value();
```

Die fünf Ports und ihre Verwendung in der Bridge:

| Port | Zweck | Verwendet von |
|---|---|---|
| `HsmRsaEncryption` / `HsmRsaEncryptionExecutor` | RSA-PKCS#1v1.5, ein Klartextblock rein/raus | `HsmRsaPublicKeyKeyEncryptionMethodGenerator` (PKESK bauen), `HsmRsaPublicKeyDataDecryptorFactory` (Sitzungsschlüssel wiederherstellen) |
| `HsmAesEncryption` / `HsmAesEncryptionExecutor` | AES in einem von vier Modi (`ECB`/`CBC`/`CFB`/`GCM`), Sitzungsschlüssel als Klartextwert (kein Handle, siehe Abschnitt 4) | `HsmCfbEngine` (ECB als CFB-Baustein), `HsmAeadChunkCodec` (GCM), `HsmAesKeyWrap` (ECB als RFC-3394-Baustein) |
| `HsmSignature` / `HsmSignatureExecutor` | Ein Algorithmus-Port für RSA/ECDSA/EdDSA/ML-DSA, operiert immer auf einem vorab lokal berechneten Digest | `HsmBackedPGPContentSignerBuilder` |
| `HsmKeyAgreement` / `HsmKeyAgreementExecutor` | ECDH-Punktmultiplikation, kurvenparametrisiert (`X25519`/`P256`/`P384`), lokaler Handle × Peer-Handle → Shared Secret | `HsmEcdhPublicKeyKeyEncryptionMethodGenerator`, `HsmEcdhPublicKeyDataDecryptorFactory` |
| `HsmKeyEncapsulation` / `HsmKeyEncapsulationExecutor` | ML-KEM-768 Encapsulate/Decapsulate | **nicht verwendet** — PQC ist außerhalb des Scopes dieser Iteration (siehe Abschnitt 6) |

Bewusst algorithmusagnostische Ports (`HsmSignature`, `HsmKeyAgreement`) statt eines Ports pro
Algorithmus: spiegelt reale CCA-Digital-Signature-Verben, die den Algorithmus per
Rule-Array-Keyword statt per eigenem Verb auswählen.

**Schlüsselmaterial-Adressierung — die eine Ausnahme:** Alle Ports außer `HsmAesEncryption`
adressieren asymmetrisches Schlüsselmaterial ausschließlich über `HsmKeyHandle` (opaker Alias,
kein Rohmaterial). `HsmAesEncryptionRequest` trägt den AES-Sitzungsschlüssel dagegen als rohen
`ByteSequence`-Wert — dokumentierte Abweichung, weil der Sitzungsschlüssel in dieser PoC
ephemer ist, pro Nachricht neu erzeugt wird (`SymmetricSessionKeyGenerator`, lokal, mangels
Hsm-Keygen-Port) und ohnehin sofort für Empfänger verpackt wird. Entspricht dem
"Clear-Key"-Modus realer symmetrischer HSM-Verben (z. B. CCA Symmetric Key Encipher/Decipher
mit Klartextschlüssel) im Gegensatz zu deren "Secure-Key"-Varianten.

## 3. Die beiden SEIPD-Profile

`HsmBackedPGPDataEncryptorBuilder` implementiert `PGPDataEncryptorBuilder` und bildet **beide**
Verschlüsselungsprofile über denselben `HsmAesEncryption`-Cipher-Mode-Setter ab. Welches Profil
verwendet wird, entscheidet `HsmBackedOpenPgpMessageCodec.encrypt(...)` anhand von
`PgpEncryptionProfile`:

```java
if (request.profile() == PgpEncryptionProfile.AEAD_V2) {
    dataEncryptorBuilder.setWithAEAD(AEADAlgorithmTags.GCM, AEAD_CHUNK_SIZE_EXPONENT);
    dataEncryptorBuilder.setUseV6AEAD();
} else {
    dataEncryptorBuilder.setWithIntegrityPacket(true);
}
```

### 3.1 Legacy-Profil (SEIPD v1, RFC 4880, CFB + MDC)

`build(byte[] keyBytes)` liefert einen `PGPDataEncryptor`, dessen Output-Stream Plain-CFB mit
Null-IV verwendet:

- `HsmCfbEngine` hält ein 16-Byte-Rückkopplungsregister und ruft für jeden Block
  `HsmAesEncryptionExecutor` mit `cipherMode(ECB)` auf genau diesem Register auf (nie auf dem
  Klartext/Chiffretext selbst) — das Ergebnis ist der Keystream, der per XOR mit dem
  Klartextblock verknüpft wird. Sowohl beim Ver- als auch beim Entschlüsseln wird die
  Blockchiffre im **Verschlüsselungsmodus** aufgerufen (Eigenschaft von CFB als
  selbstsynchronisierendem Modus) — daher ausschließlich `HsmCipherOperation.ENCRYPT`-Aufrufe
  gegen die HSM, auch beim Entschlüsseln der Nachricht.
- `HsmCfbOutputStream`/`HsmCfbInputStream` puffern beliebig große `write()`/`read()`-Aufrufe zu
  16-Byte-Fenstern und delegieren jedes volle (bzw. das letzte, unvollständige) Fenster an die
  Engine.
- Der MDC-Trailer (SHA-1 über den Klartext) wird lokal über `LocalSha1DigestCalculator`
  gebildet — reine Integritätssicherung ohne Geheimnisbezug, kein HSM-Aufruf nötig.

**Beim Bau entdeckte Erkenntnis** (dokumentiert im JavaDoc von `HsmCfbEngine`): Bouncy Castles
eigene Referenzimplementierung verwendet für SEIPD v1 (mit MDC) **keine** spezielle
"OpenPGP-CFB-mit-Resync"-Konstruktion. Die dortige `OpenPGPCFBBlockCipher`-Klasse mit
Resync-Logik wird nur für das ältere, MDC-lose SED-Paketformat gebraucht, das nicht Teil dieses
Scopes ist. SEIPD v1 nutzt stattdessen gewöhnliches CFB mit voller Blockrückkopplung und einem
Null-IV (`new ParametersWithIV(key, new byte[blockSize])`). Diese Bridge bildet also bewusst
*keinen* Resync nach — das wäre für SEIPD v1 schlicht falsch gewesen.

### 3.2 Modernes Profil (SEIPD v2/AEAD, RFC 9580, AES-256-GCM)

`build(byte[] key, byte[] salt)` leitet zunächst lokal per HKDF-SHA256 (RFC 9580 Section
5.13.2) aus Sitzungsschlüssel und Salt den Nachrichtenschlüssel und das 12-Byte-Nonce-Präfix ab
(`Rfc6637KeyDerivation.aeadMessageKeyAndIvMaterial`, trotz des Klassennamens auch für das
AEAD-Profil zuständig). Die eigentliche Verschlüsselung läuft Chunk-weise:

- `HsmAeadOutputStream` puffert Klartext bis zur konfigurierten Chunk-Größe (Exponent `12` →
  4096-Byte-Chunks) und verschlüsselt jeden vollen Chunk sofort.
- `HsmAeadChunkCodec.encryptChunk`/`decryptChunk` rufen `HsmAesEncryptionExecutor` mit
  `cipherMode(GCM)` auf, mit einem je Chunk-Index abgeleiteten Nonce
  (`nonceForChunk` XOR-t den Chunk-Index in die unteren 8 Byte des Basis-IV) und dem
  HKDF-Info-Wert als Additional Authenticated Data.
- Beim Schließen des Streams wird zusätzlich ein **abschließender, längenauthentisierender
  Nachrichten-Tag** über *leeren* Klartext berechnet (RFC 9580 Section 5.13.2) —
  `HsmAesEncryptionRequest` erlaubt leeren `input` explizit nur für `GCM`, alle anderen Modi
  lehnen das ab.

Entschlüsselung läuft spiegelbildlich über `HsmSymmetricDecryptorSupport.createAeadDecryptor`
und `HsmAeadChunkCodec.decryptChunk`/`verifyFinalTag`.

Beide Profile teilen sich denselben `HsmAesEncryptionExecutor`-Port — nur `cipherMode` und die
umgebende Framing-Logik unterscheiden sich. Das demonstriert, dass beliebige symmetrische
Betriebsmodi über eine einzige, algorithmusagnostische Hsm-Primitive abbildbar sind, solange
diese einen Cipher-Mode-Setter besitzt (siehe Projektkontext).

## 4. Schlüssel-Handle-Modellierung: kein `PGPSecretKey` mit echtem Material

Diese Bridge erzeugt und liest **niemals** ein `PGPSecretKey`-Objekt mit echtem privatem
Schlüsselmaterial. Stattdessen:

- `PgpKeyMaterialCodec.toPgpPublicKey(...)` baut aus dem projekteigenen `PgpPublicKey` ein
  `org.bouncycastle.openpgp.PGPPublicKey` — reine Paket-Framing-Übersetzung.
- Für den Signaturschritt verlangt BCs `PGPSignatureGenerator.init(...)` aus API-Gründen ein
  `PGPPrivateKey`-Objekt. `PgpKeyMaterialCodec.placeholderPrivateKey(...)` baut dafür einen
  **opaken Platzhalter**: ein `PGPPrivateKey`, dessen `BCPGKey` (`NoMaterialBcpgKey`) keine
  echten Daten trägt (`getEncoded()` liefert ein leeres Array, `getFormat()` liefert
  `"OPAQUE-HSM-HANDLE"`). Der tatsächliche private Schlüssel bleibt ausschließlich als
  `HsmKeyHandle` bekannt und verlässt nie die HSM-Domäne — analog zum
  Smartcard/OpenPGP-Card-Modell (`gpg-agent` gegen eine Card: auch dort verlässt der private
  Schlüssel nie die Karte, `gpg` bekommt nur ein Ergebnis zurück).
- Der jeweilige `HsmKeyHandle` reist parallel zum `PGPPublicKey`/`PGPPrivateKey`-Platzhalter
  durch die Bridge-Klassen (Konstruktor-Parameter, z. B.
  `HsmRsaPublicKeyKeyEncryptionMethodGenerator(recipientPublicKey, executor,
  recipientKeyHandle)`) und wird erst beim eigentlichen HSM-Aufruf verwendet.

Das ist dieselbe Idee wie in Abschnitt 1: BC bekommt genug Struktur, um das Paketformat korrekt
zu bauen (Key-ID, Public-Key-Algorithmus-Tag, Hash-Algorithmus), aber niemals genug, um selbst
zu signieren oder zu entschlüsseln.

## 5. Bekannte Einschränkungen dieser PoC-Iteration

Diese Iteration deckt RSA sowie ECC ab (natives X25519/Ed25519 nach RFC 9580 und das
klassische ECDH/ECDSA-Fallback-Profil nach RFC 6637 über P-256/P-384). Folgende Punkte sind
bewusste, dokumentierte Lücken — nicht beschönigt:

**EdDSA/Ed25519-Signieren ist nicht interoperabel mit echtem "Pure EdDSA".** Der
`HsmSignature`-Port ist bewusst algorithmusagnostisch und operiert einheitlich auf einem lokal
vorberechneten Digest (`HsmSignatureRequest.digest()`), nicht auf der Rohnachricht. Für
RSA-PKCS#1v1.5 und ECDSA ist das das übliche "hash-then-sign"-Schema — konsistent mit externen
Tools. Für Ed25519 weicht das jedoch vom OpenPGP-Standardfall ab: "Pure EdDSA" signiert
üblicherweise direkt über die Rohnachricht, nicht über einen vorberechneten Digest.
`HsmBackedPGPContentVerifierBuilderProvider` verifiziert daher konsequent gegen denselben
SHA-256-Digest, den auch `HsmBackedPGPContentSignerBuilder` beim Signieren verwendet hat — die
Bridge ist also intern konsistent (eigene Signaturen lassen sich mit dem eigenen Verifier
prüfen), aber mit `gpg` oder unverändertem Bouncy Castle erzeugte bzw. erwartete
Ed25519-Signaturen sind **nicht** kompatibel. Nur RSA und ECDSA sind vollständig
interop-getestet (siehe embedded CLI-Demo, 9/9 erfolgreiche Durchläufe für RSA, natives X25519
und klassisches ECDH/ECDSA-P-256 — X25519 betrifft hier nur die Verschlüsselung, nicht
Ed25519-Signaturen).

**Die ECDH-Peer-Handle-Auflösung beim Entschlüsseln ist ein Test-Fixture-Workaround, keine
produktionsreife Lösung.** `HsmKeyAgreementRequest` adressiert die Gegenstelle einer
ECDH-Operation ausschließlich über `HsmKeyHandle` — unter der Annahme, dass Gegenstellen-
Schlüssel vorab im HSM als importierte Public-Key-Token registriert sind. Beim Verschlüsseln
ist das unproblematisch: die Gegenstelle ist der Empfänger, dessen Handle bereits explizit
vorliegt. Beim Entschlüsseln ist die Gegenstelle jedoch der Sender-Schlüssel, dessen
öffentlicher Punkt erst beim Parsen des empfangenen Pakets bekannt wird —
`OpenPgpDecryptionRequest` trägt bewusst keine Absenderreferenz (der Sender-Schlüssel ist laut
Anwendungsschicht ohnehin ein vorab im HSM vorhandener, statischer Schlüssel statt eines je
Nachricht neu erzeugten ephemeren Schlüssels; echtes RFC-9580-Forward-Secrecy ist explizit
nicht im Scope). `EphemeralPeerKeyHandles.deriveFrom(...)` überbrückt diese Lücke, indem sie
denselben Handle deterministisch aus dem öffentlichen Punkt selbst ableitet
(`"ecdh-peer-" + SHA-256(rawPublicKeyMaterial)` als Hex). Eine Testinfrastruktur muss den
Sender-Schlüssel daher zusätzlich zu seinem eigentlichen Alias auch unter diesem abgeleiteten
Handle im HSM-Schlüsselspeicher registrieren (siehe `InMemoryHsmKeyStore`-Nutzung in Tests und
im CLI-Demo-Adapter). Ein echter ICSF-Adapter müsste hier stattdessen einen echten
Public-Key-Import-Schritt vor der eigentlichen Schlüsselaustausch-Operation durchführen.

**PQC (ML-KEM-768+X25519, ML-DSA-65+Ed25519, RFC 9980) ist nicht implementiert.** Die Ports
`HsmKeyEncapsulation`/`HsmKeyEncapsulationExecutor` existieren bereits (inklusive Dummy-Adapter,
`DummyHsmKeyEncapsulationExecutor`) und `HsmSignatureAlgorithm.ML_DSA_65_ED25519` ist als
Enum-Wert definiert — aber keine Bridge-Klasse in `adapters/outbound/openpgp/bc` nutzt sie. Der
Grund ist paketformatseitig: die in diesem Projekt verwendete `bcpg`-Version (1.85) kennt die
komposite Paketkodierung für RFC-9980-Algorithmus-IDs 30 (ML-DSA-65+Ed25519) und 35
(ML-KEM-768+X25519) noch nicht. `PgpKeyMaterialCodec.toBcpgKey(...)` wirft für alle
Nicht-RSA/ECC-Algorithmen explizit eine `IllegalArgumentException` mit dem Hinweis "PQC ist
explizit außerhalb des Scopes dieser Iteration". Eine spätere Iteration müsste die
Paket-/MPI-Strukturen für komposite Public-Key-, Signatur- und Session-Key-Pakete selbst
nachbauen, statt sie von `bcpg` zu bekommen.

**X25519-Unterstützung auf echtem CCA/ICSF ist unbestätigt.** Der CCA-Realitätscheck (siehe
Projektplan) zeigt: öffentliche IBM-Dokumentation belegt für Crypto Express8S+ explizit
EdDSA-Signaturunterstützung (CSNDDSG/CSNDDSV, APAR OA58880) und klassisches NIST/Brainpool-ECDH,
aber **keine** explizite X25519-Schlüsselvereinbarung. `HsmEllipticCurve.X25519` ist in dieser
PoC trotzdem als gleichwertige Option neben `P256`/`P384` modelliert — der Port
`HsmKeyAgreement` bleibt bewusst kurvenagnostisch, damit ein echter ICSF-Adapter algorithmisch
nicht umgebaut werden müsste, sollte X25519 doch verfügbar sein. Ist es das nicht, ist die
dokumentierte Fallback-Empfehlung, im echten Adapter auf klassisches NIST-Kurven-ECDH (RFC 6637,
`P256`/`P384`) auszuweichen, statt X25519 zu erzwingen. Das betrifft auch die PQC-Komposit-KEM
(Alg-ID 35), die X25519 als klassische Komponente nutzt, und ist damit ein offenes Risiko für
einen echten ICSF-Adapter, nicht nur für das reine ECC-Profil.

## 6. Demo selbst ausführen

Kurzfassung — Details (Konfiguration, Voraussetzungen) stehen in der Projekt-`README.md`:

```bash
mvn clean install       # Build, alle Tests, ArchUnit-Regeln
mvn spring-boot:run     # Startet den CommandLineRunner (adapters/inbound/cli)
```

Der CLI-`CommandLineRunner` (`OpenPgpDemoRunner`) provisioniert Demo-Schlüssel
(`DemoKeyMaterial`) im `InMemoryHsmKeyStore`, führt Verschlüsseln→Entschlüsseln und
Signieren→Verifizieren für die unterstützten Algorithmusprofile durch und beendet sich danach
wieder — kein Dauerbetrieb, keine REST-Fassade.
