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

Typischer Aufruf aus einer Bridge-Klasse (`HsmAesKeyWrap`, ein einzelner RFC-3394-Blockschritt):

```java
HsmAesEncryptionRequest request = HsmAesEncryption.builder()
        .sessionKey(ByteSequence.of(kek))
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
| `HsmAesEncryption` / `HsmAesEncryptionExecutor` | AES in einem von vier Modi (`ECB`/`CBC`/`CFB`/`GCM`), Sitzungsschlüssel als Klartextwert (kein Handle, siehe Abschnitt 4) | `HsmAeadChunkCodec` (GCM), `HsmAesKeyWrap` (ECB als RFC-3394-Baustein) |
| `HsmSignature` / `HsmSignatureExecutor` | Ein Algorithmus-Port für RSA/ECDSA/EdDSA/ML-DSA, operiert immer auf einem vorab lokal berechneten Digest | `HsmBackedPGPContentSignerBuilder` |
| `HsmKeyAgreement` / `HsmKeyAgreementExecutor` | ECDH-Punktmultiplikation, kurvenparametrisiert (`X25519`/`P256`/`P384`), lokaler Handle × Peer-Handle → Shared Secret | `HsmEcdhPublicKeyKeyEncryptionMethodGenerator`, `HsmEcdhPublicKeyDataDecryptorFactory` |
| `HsmKeyEncapsulation` / `HsmKeyEncapsulationExecutor` | ML-KEM-768 Encapsulate/Decapsulate | `HsmCompositeMlKemKeyEncryptionMethodGenerator`, `HsmCompositeMlKemPublicKeyDataDecryptorFactory` (siehe Abschnitt 7) |

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

## 3. Das SEIPD-v2/AEAD-Profil

`HsmBackedPGPDataEncryptorBuilder` implementiert `PGPDataEncryptorBuilder` und bildet
ausschließlich SEIPD v2/AEAD (RFC 9580) über den `HsmAesEncryption`-Cipher-Mode-Setter ab.
`HsmBackedOpenPgpMessageCodec.encrypt(...)` konfiguriert dafür immer denselben AEAD-Modus:

```java
dataEncryptorBuilder.setWithAEAD(AEADAlgorithmTags.GCM, AEAD_CHUNK_SIZE_EXPONENT);
dataEncryptorBuilder.setUseV6AEAD();
```

**Warum kein SEIPD v1 (RFC 4880, Plain-CFB + MDC)?** Frühere Iterationen dieser Bridge
unterstützten beide Profile parallel (Plain-CFB mit Null-IV über ein HSM-ECB-Rückkopplungsregister,
MDC-Trailer lokal per SHA-1). Ein Review der Implementierung kam zu dem Schluss, dass ein
zusätzliches, kryptographisch schwächeres Profil ohne fachlichen Mehrwert für diese PoC nur
unnötigen Implementierungs- und Pflegeaufwand bedeutet hätte — das Profil wurde daraufhin bewusst
entfernt. `HsmBackedPGPDataEncryptorBuilder.build(byte[])` (die von Bouncy Castle nur für dieses
Profil aufgerufene Methode) sowie die entsprechenden `createDataDecryptor(boolean, int, byte[])`-
Überladungen aller `PublicKeyDataDecryptorFactory`-Implementierungen dieser Bridge werfen daher
explizit eine `PGPException`, statt das Profil stillschweigend zu unterstützen.

`build(byte[] key, byte[] salt)` leitet zunächst lokal per HKDF-SHA256 (RFC 9580 Section
5.13.2, über Bouncy Castles eigenen `HKDFBytesGenerator` statt einer selbst geschriebenen
Extract-and-Expand-Schleife) aus Sitzungsschlüssel und Salt den Nachrichtenschlüssel und das
12-Byte-Nonce-Präfix ab (`Rfc6637KeyDerivation.aeadMessageKeyAndIvMaterial`, trotz des
Klassennamens auch für das AEAD-Profil zuständig). Die eigentliche Verschlüsselung läuft
Chunk-weise:

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
und `HsmAeadChunkCodec.decryptChunk`/`verifyFinalTag`. Anders als ein Klartext-Stream kann die
AEAD-Nutzlast beim Entschlüsseln nicht Chunk-für-Chunk an den Aufrufer durchgereicht werden,
bevor der abschließende Nachrichten-Tag geprüft ist — sonst könnte ein Angreifer die Nachricht
unbemerkt kürzen (Truncation-Angriff). `createAeadDecryptor` liest daher den kompletten
Ciphertext vorab ein, entschlüsselt und verifiziert alle Chunks samt Nachrichten-Tag, und liefert
erst danach den fertigen Klartext zurück.

Denselben `HsmAesEncryptionExecutor`-Port nutzt auch `HsmAesKeyWrap` (RFC-3394-Schlüsselverpackung,
`cipherMode(ECB)`) — nur `cipherMode` und die umgebende Framing-Logik unterscheiden sich. Das
demonstriert, dass beliebige symmetrische Betriebsmodi über eine einzige, algorithmusagnostische
Hsm-Primitive abbildbar sind, solange diese einen Cipher-Mode-Setter besitzt (siehe Projektkontext).

## 4. Schlüssel-Handle-Modellierung: kein `PGPSecretKey` mit echtem Material

Diese Bridge erzeugt und liest **niemals** ein `PGPSecretKey`-Objekt mit echtem privatem
Schlüsselmaterial. Stattdessen:

- `PgpKeyMaterialCodec.toPgpPublicKey(...)` baut aus dem projekteigenen `PgpPublicKey` ein
  `org.bouncycastle.openpgp.PGPPublicKey` — reine Paket-Framing-Übersetzung. Den dafür
  benötigten `BcKeyFingerprintCalculator` reicht der Aufrufer als Parameter durch, statt ihn
  lokal zu instanziieren — `OpenPgpIcsfPocApplication.bcKeyFingerprintCalculator()` stellt ihn
  als einzige, injizierte Instanz bereit (analog zur `InMemoryHsmKeyStore`-Bean-Definition
  daneben), statt dass mehrere Klassen redundant je eine eigene, versteckt gekoppelte Instanz
  anlegen.
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

**Die PQC-Verschlüsselung ML-KEM-768+X25519 (RFC 9980, Algorithmus-ID 35) ist implementiert —
die PQC-Signatur ML-DSA-65+Ed25519 (Algorithmus-ID 30) noch nicht.** Siehe Abschnitt 7 für die
Details der kompositen Verschlüsselung. `HsmSignatureAlgorithm.ML_DSA_65_ED25519` ist zwar als
Enum-Wert definiert, aber keine Bridge-Klasse nutzt ihn — RFC 9980 Section 3.5 erlaubt PQC-Keys
nur ab v6-Schlüsseln/-Signaturen, mit der einzigen Ausnahme von Algorithmus-ID 35 (auch in
v4-Verschlüsselungs-Subkeys zulässig, siehe Abschnitt 7.1) — und diese PoC modelliert
ausschließlich v4-Schlüsselpakete (siehe `PgpKeyMaterialCodec.FIXED_CREATION_TIME`/
`PublicKeyPacket.VERSION_4`). v6-Paket-Unterstützung (Voraussetzung für ML-DSA-65+Ed25519) ist
für eine spätere Iteration vorgesehen.

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

Was diese vier Punkte für einen produktiven Einsatz konkret bedeuten (Aufwand, Reihenfolge,
Handlungsoptionen), steht gebündelt in `docs/technical/production-readiness.md`. Hintergrund zu
Post-Quantum-Kryptographie in OpenPGP allgemein (nicht projektspezifisch) steht in
`docs/technical/pqc-notes.md`.

## 7. Komposite Post-Quantum-Verschlüsselung (ML-KEM-768+X25519, RFC 9980)

Algorithmus-ID 35 kombiniert ML-KEM-768 (Post-Quantum-KEM, FIPS-203) mit X25519 (klassisches
ECDH-KEM) zu einem einzigen hybriden Verschlüsselungsverfahren. Diese Bridge implementiert das
komplett in `adapters/outbound/openpgp/bc`, ohne core/domain oder core/app zu verändern — beide
waren dafür bereits vorbereitet (`PgpPublicKeyAlgorithm.ML_KEM_768_X25519`,
`requiresSenderKeyAgreementKey()`, `HsmKeyEncapsulation`/`HsmKeyEncapsulationExecutor`).

### 7.1 Warum `bcpg-jdk18on` 1.85 hier nicht "einfach mitspielt"

Anders als bei RSA/ECDH/X25519 kann diese Bridge für Algorithmus-ID 35 **nicht** die üblichen
BC-Basisklassen wiederverwenden — `bcpg` 1.85 kennt diese Algorithmus-ID an mehreren Stellen
schlicht nicht:

- `PublicKeyKeyEncryptionMethodGenerator`s Konstruktor und `encodeEncryptedSessionInfo(byte[])`
  prüfen den Algorithmus-Tag gegen eine feste, einprogrammierte Liste (RSA, ElGamal, ECDH,
  X25519/X448, …) und brechen für 35 mit `IllegalArgumentException`/`PGPException` ab.
- `PublicKeyEncSessionPacket`s **lesender** Konstruktor (der beim Parsen eines PKESK-Pakets über
  `BCPGInputStream` aufgerufen wird) hat einen Algorithmus-Switch ohne Eintrag für 35 und wirft
  eine `IOException` — noch bevor eigener Code eingreifen könnte.

Für **Verschlüsselung** genügt es, `PGPKeyEncryptionMethodGenerator` (das schlanke Interface,
nicht die Basisklasse mit der Algorithmus-Prüfung) direkt zu implementieren
(`HsmCompositeMlKemKeyEncryptionMethodGenerator`) und das resultierende Paket über
`PublicKeyEncSessionPacket`s **öffentliche** Kodierungs-Fabrikmethoden
(`createV3PKESKPacket`/`createV6PKESKPacket`) zu bauen — diese sind, anders als der lesende
Konstruktor, nicht auf bekannte Algorithmen beschränkt.

Für **Entschlüsselung** reicht das nicht: `PGPObjectFactory`/`PGPEncryptedDataList` können ein
PKESK-Paket mit Algorithmus-ID 35 grundsätzlich nicht einlesen (siehe oben), sodass dieser Weg
für die gesamte Nachricht versperrt ist, nicht nur für das PKESK-Paket selbst. Der Codec parst
das PKESK-Paket deshalb manuell (siehe 7.3) und erzeugt anschließend ein
`org.bouncycastle.openpgp.PGPSessionKeyEncryptedData` — BCs Gegenstück zu
`gpg --override-session-key`, das die SEIPD-v2/AEAD-Entschlüsselungs-/Chunk-Verifikationslogik
fertig mitbringt — über dessen
paketsichtbaren Konstruktor per Reflection (`HsmBackedOpenPgpMessageCodec.newSessionKeyEncryptedData(...)`).
Das funktioniert ohne `--add-opens`, weil sowohl der gepackte Spring-Boot-Jar (`java -jar`) als
auch die Maven-Surefire-Testausführung `bcpg-jdk18on` auf dem Classpath (unbenanntes Modul) statt
auf dem Modulpfad laden.

### 7.2 Schlüssel-Kombinierer (`multiKeyCombine`, RFC 9980 Section 4.2.1)

`HsmCompositeMlKemKeyCombiner` implementiert die KEK-Ableitung wortwörtlich:

```
KEK = SHA3-256(mlkemKeyShare || ecdhKeyShare || ecdhCipherText || ecdhPublicKey ||
               algId || domSep || len(domSep))
```

mit `domSep` = UTF-8 `"OpenPGPCompositeKDFv1"` (21 Oktette). Lokale, deterministische Berechnung
über Standard-JDK-`MessageDigest` — beide Shared Secrets sind zu diesem Zeitpunkt bereits die
(nicht mehr geheimen) Ausgaben der beiden KEM-Operationen, kein HSM-Bezug nötig. Der
resultierende KEK verpackt den Sitzungsschlüssel per RFC-3394-AES-Key-Wrap — genau dieselbe
`HsmAesKeyWrap`-Klasse, die auch das klassische ECDH-Profil bereits verwendet (siehe Abschnitt 4
des Projektplans zur Wiederverwendung).

### 7.3 PKESK-Byte-Layout (RFC 9980 Section 4.3.1)

`HsmCompositeMlKemPkeskCodec` kapselt das gesamte Byte-Layout, kryptographiefrei:

- **Algorithmus-spezifischer Teil:** `ecdhCipherText(32) || mlkemCipherText(1088) ||
  len(C,symAlgId)(1) || [symAlgId(1), nur v3] || C`.
- **Paket-Rahmung:** ein selbst geschriebener, minimaler Leser für OpenPGP-Paket-Header (Tag +
  Neu-Format-Länge) — reine Framing-Logik, unabhängig vom Algorithmus, die nur deshalb selbst
  implementiert werden musste, weil `BCPGInputStream` sie nicht isoliert vom
  algorithmus-spezifischen Parsing anbietet (siehe 7.1).
- **PKESK-Kopf:** Version (3 oder 6), Schlüssel-ID (v3) bzw. Schlüsselversion+Fingerabdruck (v6),
  Algorithmus-Byte.

### 7.4 Komposites Schlüsselmaterial und die Zwei-Handle-Konvention

`CompositeMlKemKeyMaterial` setzt das öffentliche Schlüsselmaterial zusammen/zerlegt es
(`ecdhPublicKey(32) || mlkemPublicKey(1184)`, RFC 9980 Section 4.3.2.1, fixed-length ohne
MPI-Kodierung) und definiert die Handle-Konvention für Komposit-Empfänger: `PgpKeyReference`
trägt genau einen `HsmKeyHandle`, das darunter im HSM hinterlegte Schlüsselobjekt ist aber ein
eigenständiges JCA-`KeyPair` je Teilalgorithmus. Diese Bridge behandelt den primären Handle als
den des **ML-KEM-Teilschlüssels** und leitet den Handle des **X25519-Teilschlüssels**
deterministisch per Namenskonvention ab (`<alias>-x25519`) — dasselbe Prinzip wie
`EphemeralPeerKeyHandles` für das native X25519-Profil (siehe Abschnitt 5). Wer einen
Komposit-Empfänger registriert (CLI-Demo, Testinfrastruktur), muss beide Teilschlüssel unter den
jeweils passenden Handles ablegen.

Für die eigentliche ECDH-KEM-Hälfte (Section 4.1.1.1) gilt dieselbe PoC-Vereinfachung wie beim
nativen X25519-Profil: statt eines je Nachricht neu erzeugten ephemeren Senderschlüssels wird ein
vorab im HSM vorhandener, statischer Sender-Schlüssel verwendet (`senderKeyAgreementKey`) — die
ECDH-Punktmultiplikation läuft über `HsmKeyAgreementExecutor`, exakt wie in
`HsmEcdhPublicKeyKeyEncryptionMethodGenerator`.

`PgpKeyMaterialCodec.CompositeMlKemPublicBCPGKey` bildet die Rohbytes als BC-`BCPGKey` ab. Sie
**muss** `BCPGObject` erweitern (nicht nur `BCPGKey` implementieren, wie das nie tatsächlich
serialisierte `NoMaterialBcpgKey`) — `PublicKeyPacket.getEncodedContents()`, von der
Fingerabdruckberechnung und jedem echten Paket-Schreibvorgang durchlaufen, castet das
Schlüsselfeld intern unbedingt nach `BCPGObject`.

### 7.5 Korrektheitsnachweis: RFC-9980-Testvektoren statt Interop-Test

Für RSA/ECDH/X25519 demonstriert `HsmBackedOpenPgpMessageCodecInteropTest`
Standard-Interoperabilität, indem unverändertes Bouncy-Castle-JCE-API eine von dieser Bridge
erzeugte Nachricht liest. Für Algorithmus-ID 35 ist das **nicht möglich** — dieselbe
`bcpg`-1.85-Lücke (siehe 7.1), die die eigene Bridge zu den oben beschriebenen Workarounds
zwingt, verhindert auch, dass unverändertes Bouncy Castle (oder irgendein anderes derzeit
verfügbares Tool) eine Nachricht mit Algorithmus-ID 35 überhaupt lesen könnte.

Der Korrektheitsnachweis läuft stattdessen über die offiziellen RFC-9980-Testvektoren
(Appendix A.2, v4-Schlüssel — die für diese PoC relevante Zielgröße laut RFC Section 3.5):

- `HsmCompositeMlKemKeyCombinerTest` reproduziert byte-exakt sowohl den `KEK`-Wert als auch (via
  `HsmAesKeyWrap`) den Sitzungsschlüssel aus Appendix A.2.3 (v3-PKESK) und A.2.4 (v6-PKESK), mit
  `mlkemKeyShare`/`ecdhKeyShare` direkt aus dem RFC-Text und `ecdhCipherText`/`ecdhPublicKey`
  lokal aus den RFC-eigenen armored Schlüssel-/Nachrichten-Blöcken extrahiert.
- `HsmCompositeMlKemPkeskCodecTest` verifiziert das PKESK-Byte-Layout direkt gegen die
  entschachtelten (armored, aber sonst unveränderten) RFC-Nachrichten aus Appendix A.2.3/A.2.4.

**Nicht verifiziert:** das Parsen des RFC-eigenen Secret-Key-Blocks durch diese PoC selbst — das
PoC-Schlüsselmodell kennt nur `HsmKeyHandle`-referenzierte Schlüssel, kein Parsen echter
Secret-Key-Pakete (dieselbe Einschränkung wie bei jedem anderen Algorithmus dieser Bridge). Der
vollständige Ende-zu-Ende-Rundlauf-Nachweis (Verschlüsseln→Entschlüsseln) läuft daher mit
PoC-eigenen, nicht mit RFC-Testschlüsseln — siehe
`HsmBackedOpenPgpMessageCodecIntegrationTest.encryptThenDecrypt_givenCompositeMlKem768X25519Recipient_thenRecoversPlaintext`.

## 8. Demo selbst ausführen

Kurzfassung — Details (Konfiguration, Voraussetzungen) stehen in der Projekt-`README.md`:

```bash
mvn clean install       # Build, alle Tests, ArchUnit-Regeln
mvn spring-boot:run     # Startet den CommandLineRunner (adapters/inbound/cli)
```

Der CLI-`CommandLineRunner` (`OpenPgpDemoRunner`) provisioniert Demo-Schlüssel
(`DemoKeyMaterial`) im `InMemoryHsmKeyStore`, führt Verschlüsseln→Entschlüsseln und
Signieren→Verifizieren für die unterstützten Algorithmusprofile durch und beendet sich danach
wieder — kein Dauerbetrieb, keine REST-Fassade.
