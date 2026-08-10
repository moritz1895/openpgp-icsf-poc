# openpgp-icsf-poc — Plan

> **Hinweis:** Dies ist der ursprüngliche, mit dem Nutzer abgestimmte Architektur- und Umsetzungsplan (Snapshot). Die tatsächliche Umsetzung wich in Details davon ab (z. B. wurde die Bouncy-Castle-Bridge-Implementierung mangels eines passenden spezialisierten Agenten für generische Outbound-Infrastruktur-Adapter nicht von core-coder, sondern von einem entsprechend beauftragten Agenten übernommen; `OpenPgpMessageCodec` wurde nachträglich neu zugeschnitten). Der aktuelle Stand von Scope und bekannten Einschränkungen steht im README und in `docs/technical/openpgp-hsm-bridge.md` — dieses Dokument dient als historischer Kontext der Architekturentscheidungen (insbesondere der CCA/ICSF-Realitätscheck).

## Context

Ausgangslage (hypothetisch, laut Nutzer): Es existiert bereits eine hausinterne Krypto-Bibliothek ("kprypto"), die kryptographische Verfahren als Bausteine bereitstellt (z. B. JWE über `HsmAesEncryption`/`HsmRsaEncryption`) und dabei ausschließlich über eine **proprietäre HSM-Primitives-Schnittstelle** arbeitet — ein generisches Java-Interface nach Builder-Prinzip, das Ausführungsobjekte zusammenbaut und ausführt. Diese Schnittstelle hat **nichts mit JCE oder PKCS#11 zu tun**. Konkreter Backend-Adapter ist ICSF auf z/OS, dessen Details für diese PoC irrelevant sind — wir programmieren ausschließlich gegen die abstrakten Hsm-Primitives.

Ziel dieser PoC: Die Bibliothek um **OpenPGP** (RFC 4880 / RFC 9580 "Crypto Refresh") erweitern — Verschlüsseln, Entschlüsseln, Signieren, Verifizieren —, wobei sämtliche geheimen Schlüsseloperationen (RSA privat, AES) über die Hsm-Primitives laufen und niemals über JCE-Provider. Etablierte Libraries (Bouncy Castle) dürfen für die OpenPGP-**Paketformat/Framing**-Logik verwendet werden, nicht aber für die eigentliche Schlüsseloperation.

Repo `moritz1895/openpgp-icsf-poc` (private) wurde bereits angelegt, noch ohne Inhalt/Commits.

**Scope-Entscheidungen (mit Nutzer abgestimmt):**
- Beide SEIPD-Profile: klassisch (v1, CFB+MDC, RFC 4880) **und** modern (v2, AEAD, RFC 9580) — zeigt, dass beliebige symmetrische Betriebsmodi über die proprietäre Hsm-Schnittstelle abbildbar sind. AEAD-Algorithmus: **AES-256-GCM** statt OCB (Begründung siehe CCA-Realitätscheck unten).
- Signieren/Verifizieren gehört zum Scope (nicht nur Encrypt/Decrypt).
- Schlüssel (RSA, ECC, PQC) werden als **vorab im HSM vorhandene Key-Handles** angenommen (kein Hsm-Keygen-Port in dieser PoC); der öffentliche Schlüssel wird separat als Wert bereitgestellt.
- **Erweiterung (diese Iteration):** zusätzlich zu RSA jetzt auch native OpenPGP-ECC-Algorithmen (Ed25519/X25519, ECDSA) sowie die OpenPGP-Post-Quantum-Erweiterung (RFC 9980) im Scope — siehe eigener Abschnitt unten.

## ECC & Post-Quantum-Kryptografie in OpenPGP

**ECC (RFC 9580):** OpenPGP sieht klassisch (RFC 6637, weiter gültig) ECDSA/ECDH mit NIST-Kurven (P-256/P-384/P-521) und Brainpool vor. RFC 9580 ("Crypto-Refresh") nimmt zusätzlich **Ed25519/Ed448** (EdDSA, Signatur) und **X25519/X448** (Montgomery-Kurven, ECDH-Verschlüsselung) nativ als eigene, bevorzugte Algorithmen auf. Für diese PoC: Ed25519 + X25519 als primäres "modernes" ECC-Profil, klassisches NIST/Brainpool-ECDSA/ECDH als Fallback-Profil (relevant für den CCA-Realitätscheck, siehe unten).

**Post-Quantum (RFC 9980, `draft-ietf-openpgp-pqc-17`, publiziert 13.01.2026, erweitert RFC 9580):** Definiert **komposite** (PQ/T-Hybrid) Verfahren — reines PQC ist für Verschlüsselung nicht vorgesehen, nur in Kombination mit einer klassischen ECDH-Komponente als Pre-Quantum-Fallback:

| Alg-ID | Verfahren | Typ | Status im Draft |
|---|---|---|---|
| 35 | ML-KEM-768 + X25519 | Verschlüsselung (KEM) | MUST |
| 36 | ML-KEM-1024 + X448 | Verschlüsselung (KEM) | SHOULD |
| 30 | ML-DSA-65 + Ed25519 | Signatur | MUST |
| 31 | ML-DSA-87 + Ed448 | Signatur | SHOULD |
| 32–34 | SLH-DSA-SHAKE-128s/128f/256s | Signatur (standalone, kein Hybrid) | MAY |

**Scope dieser PoC:** nur die beiden MUST-Kombinationen — **ID 35 (ML-KEM-768+X25519)** für Verschlüsselung und **ID 30 (ML-DSA-65+Ed25519)** für Signaturen. SHOULD-Varianten (448-Kurven) und SLH-DSA (standalone, hash-basiert) sind für spätere Iterationen vorgesehen (siehe "Offene Punkte"), da sie den Scope einer PoC sonst sprengen und architektonisch keine neuen Muster hinzufügen — nur weitere Algorithmus-Parametrisierungen derselben Ports.

Bouncy Castle unterstützt seit 1.79 die rohen PQC-Primitiven ML-KEM/ML-DSA/SLH-DSA (NIST-Finalversionen, Stand 08/2024); die Einbindung auf **OpenPGP-Paketebene** (Alg-IDs 30–36, komposite Kodierung) in `bcpg` muss gegen die konkret verwendete BC-Version geprüft werden — falls die verwendete `bcpg`-Version RFC 9980 auf Paketebene noch nicht abbildet, müssen die neuen Paket-/MPI-Strukturen (komposite Public-Key-/Signature-/Session-Key-Pakete) in der PoC selbst nachgebaut werden. Das ist ein Risiko-Punkt, der in Schritt 2 (Projektgerüst) früh per Spike zu klären ist, bevor die Bridge-Adapter entstehen.

### CCA/ICSF-Realitätscheck (Crypto Express8S+, aktuelles ICSF)

Ziel: nicht gegen ICSF programmieren, aber die Hsm-Primitives-Ports so schneiden, dass eine reale CCA-Anbindung realistisch bliebe.

| Verfahren | CCA-Unterstützung | Quelle/Konfidenz |
|---|---|---|
| ECDSA (NIST/Brainpool) | Ja, etabliert (Digital Signature Generate/Verify, PKA-Key-Familie) | Bekannter CCA-Standardumfang |
| EdDSA (Ed25519/Ed448) | **Ja** — Digital Signature Generate/Verify (CSNDDSG/CSNDDSV) explizit um EdDSA erweitert, Edwards-Kurven auf CEX8S-Hardware | [OA58880](https://www.ibm.com/support/pages/apar/OA58880) |
| X25519/X448 (ECDH, Montgomery-Kurven) | **Nicht bestätigt** — öffentliche Doku belegt nur klassisches ECDH (NIST/Brainpool) und die o.g. Edwards-Signaturunterstützung, keine explizite X25519-Schlüsselvereinbarung gefunden | Offener Punkt, siehe unten |
| ML-DSA / CRYSTALS-Dilithium | **Ja** — Digital Signature Generate/Verify explizit erweitert (Keyword `CRDL-DSA`), auf CEX8S | [OA58880](https://www.ibm.com/support/pages/apar/OA58880), [IBM Docs: Crystals-Dilithium](https://www.ibm.com/docs/en/zos/2.5.0?topic=cryptography-crystals-dilithium-digital-signature-algorithm) |
| ML-KEM / CRYSTALS-Kyber | **Schlüssel-Lebenszyklus ja** (Generate/Import/Translate/Export über PKA-Key-Familie, AES-Transportschlüssel erforderlich); dediziertes Encapsulate/Decapsulate-Verb in öffentlicher Doku nicht auffindbar | [IBM Docs: Support for Crypto Express8 adapters, Kyber keys](https://www.ibm.com/docs/en/zos/2.5.0?topic=icsf-support-crypto-express8-adapters-kyber-keys-new-key-sizes-dilithium-digital-signature-algorithm) — Detailverb unbestätigt, als Annahme markiert |
| AES symmetrisch: ECB/CBC/CFB/OFB/CTR | Ja, etablierter Funktionsumfang von Symmetric Key Encipher/Decipher | Bekannter CCA-Standardumfang |
| AES-GCM (AEAD) | Ja, eigener AEAD-fähiger Service | Bekannter CCA-Standardumfang; **kein** Beleg für natives OCB → deshalb GCM statt OCB als AEAD-Wahl für SEIPD v2 |

**Konsequenz für die Architektur:** Die native OpenPGP-X25519-Verschlüsselung (und damit auch die PQC-Komposit-KEM ID 35, die X25519 als klassische Komponente nutzt) hat auf der realen CCA-Seite ein **unbestätigtes Enabler-Risiko**. Die PoC implementiert den `HsmKeyAgreement`-Port trotzdem algorithmusagnostisch (Kurve als Parameter im Builder) und dokumentiert diese Lücke explizit in `docs/technical/` — mit Fallback-Empfehlung, im echten ICSF-Adapter notfalls klassisches NIST-Kurven-ECDH (RFC 6637) statt X25519 zu verwenden, falls CCA das nicht atomar anbietet. Das ist genau der Realismus, den eine PoC gegen eine proprietäre, nicht vollständig bekannte HSM-Schnittstelle abbilden soll.

Die rohe AES-Einzelblock-Frage (siehe nächster Abschnitt) ist damit geklärt: CCA bietet ECB nativ — kein Problem.

## Kernidee der technischen Lösung

Bouncy Castle's `org.bouncycastle.openpgp` API ist bewusst provider-agnostisch aufgebaut: Sie kennt Extension-Points (`PGPContentSignerBuilder`, `PGPContentVerifierBuilder`, `PublicKeyKeyEncryptionMethodGenerator`, `PublicKeyDataDecryptorFactory`, `PGPDataEncryptorBuilder`/`PGPDataDecryptorFactory`), über die man **eigene** kryptographische Backends einhängen kann, statt der mitgelieferten `Bc*`/`Jce*`-Implementierungen. Wir nutzen BC ausschließlich für:
- OpenPGP-Paket-Serialisierung/-Parsing (Radix64/ASCII-Armor, Paket-Header, MPI-Kodierung, Session-Key-Framing, Signaturpaket-Struktur),
- die Orchestrierungsklassen (`PGPEncryptedDataGenerator`, `PGPSignatureGenerator`, `PGPObjectFactory` etc.),

und implementieren selbst die o. g. Extension-Points so, dass jede tatsächliche kryptographische Operation (RSA-Verschlüsseln/-Entschlüsseln, RSA-Signieren, AES-Block-/AEAD-Operation) über die Hsm-Primitives-Builder ausgeführt wird. Private Schlüssel verlassen nie die HSM-Domäne — es existiert kein `PGPSecretKey` mit echtem Schlüsselmaterial, sondern nur ein `PGPPublicKey` plus ein opakes `HsmKeyHandle` für den privaten Teil (analog zum Smartcard/OpenPGP-Card-Modell in gpg-agent).

Hashing für Signaturen erfolgt **lokal** (Standard-`MessageDigest`, unkritisch), nur der finale RSA-Sign-Schritt über den PKCS#1v1.5-DigestInfo geht an die HSM. Verifikation ist reine Public-Key-Operation ohne Geheimnis — wird lokal mit BC durchgeführt (keine HSM-Abhängigkeit nötig, da kein privates Material involviert).

## Hsm-Primitives (angenommener Bestand + Erweiterungen dieser Iteration)

`HsmAesEncryption` wird laut Vorgabe des Nutzers so angenommen, dass ihr Builder einen **Cipher-Block-Mode-Setter** besitzt (`ECB` | `CBC` | `CFB` | `GCM` | …) — analog zu einer realen CCA Symmetric-Key-Encipher/Decipher-Verb-Familie, die diese Modi bereits nativ anbietet (siehe CCA-Realitätscheck oben). Damit entfällt die ursprünglich geplante separate `HsmAesBlockCipher`-Primitive: die rohe AES-Einzelblock-Operation für den OpenPGP-CFB-Resync (SEIPD v1) wird einfach als `HsmAesEncryption`-Aufruf mit `cipherMode(ECB)` auf genau einem 16-Byte-Block realisiert — exakt das Muster, das Bouncy Castles eigene `OpenPGPCFBBlockCipher` intern verwendet (Resync ist ein Paket-Framing-Detail, kein Cipher-Modus, den eine HSM extra kennen müsste).

| Primitive | Zweck | Bemerkung |
|---|---|---|
| `HsmRsaEncryption` (bereits vorhanden) | RSA-PKCS#1v1.5-Verschlüsselung des OpenPGP-Session-Keys (PKESK-Paket, klassisches RSA-Profil) | Wiederverwendung wie bei JWE |
| `HsmAesEncryption` (bereits vorhanden, **Cipher-Mode-Setter neu genutzt**) | (a) `GCM` für SEIPD v2/AEAD, (b) `ECB`/Einzelblock als Baustein für OpenPGP-CFB-Resync bei SEIPD v1 | Kein neuer Port nötig — nur neue Nutzung des angenommenen Setters |
| `HsmSignature` (**neu**, ersetzt die zunächst geplante `HsmRsaSignature`) | Digitale Signatur über einen lokal berechneten Digest, algorithmusparametrisiert: `RSA_PKCS1V15` \| `ECDSA` \| `EDDSA` \| `ML_DSA_65_ED25519` (komposit) | Bewusst **ein** algorithmusagnostischer Port statt vier einzelne — spiegelt CCAs reale Digital-Signature-Generate/Verify-Verben, die Algorithmus per Rule-Array-Keyword auswählen, statt pro Algorithmus ein eigenes Verb zu haben |
| `HsmKeyAgreement` (**neu**) | ECDH-Shared-Secret-Ableitung, kurvenparametrisiert: `X25519` (nativ, RFC 9580) sowie `P256`/`P384`/`P521`/Brainpool (klassisch, RFC 6637-Fallback) | Deckt sowohl klassische ECC-Verschlüsselung als auch die ECDH-Hälfte der komposit-PQC-Verschlüsselung (Alg-ID 35) ab. X25519-Unterstützung auf echtem CCA unbestätigt (siehe Realitätscheck) — Port bleibt trotzdem algorithmusagnostisch |
| `HsmKeyEncapsulation` (**neu**) | ML-KEM-768 Encapsulate/Decapsulate für die PQC-Hälfte der komposit-Verschlüsselung (Alg-ID 35) | Getrennt von `HsmKeyAgreement`, da KEM (Encaps/Decaps) und ECDH (Punktmultiplikation) unterschiedliche Operationsformen sind; das Kombinieren der beiden Shared Secrets zu einem Session-Key via KDF erfolgt lokal (unkritisch, Standardvorgehen bei PQ/T-Hybriden) |

Alle Primitiven folgen dem gleichen Builder→Execution-Objekt→Executor-Pattern wie die angenommenen Bestandsprimitiven (Dummy-Definition in dieser PoC, siehe unten).

## Architektur- / Paketstruktur (Hexagonal, siehe CLAUDE.md)

```
ms.rohde.openpgpicsfpoc
 ├── ports
 │    ├── inbound        → OpenPgpEncryptionUseCase, OpenPgpSigningUseCase   (@DrivingPort)
 │    └── outbound        → HsmAesEncryption, HsmRsaEncryption (Dummy-Nachbildung),
 │                          HsmSignature, HsmKeyAgreement, HsmKeyEncapsulation (neu) (@InfrastructureServicePort)
 ├── core
 │    ├── domain          → PgpKeyHandle, PgpPublicKeyAlgorithm (RSA | ECDSA | EDDSA | X25519 | ML_KEM_768_X25519 | ML_DSA_65_ED25519),
 │    │                      PgpMessage, PgpEncryptionProfile (LEGACY_CFB_MDC | AEAD_V2)  (@DomainValueObject/@DomainEntity)
 │    └── app             → EncryptOpenPgpMessageService, DecryptOpenPgpMessageService,
 │                          SignOpenPgpMessageService, VerifyOpenPgpSignatureService (@ApplicationService)
 ├── adapters
 │    ├── inbound
 │    │    └── cli         → schlankes Spring-Boot-CommandLineRunner-Demo (@DrivingAdapter)
 │    └── outbound
 │         ├── hsm.dummy    → In-Memory/JCE-basierte Test-Doubles der Hsm-Ports (inkl. Dummy-ML-KEM/ML-DSA via BC-Rohprimitiven),
 │         │                  klar als Nicht-Produktiv-Ersatz für den späteren ICSF-Adapter markiert
 │         └── openpgp.bc   → Bridge-Klassen je Algorithmusfamilie: HsmBackedPublicKeyKeyEncryptionMethodGenerator (RSA),
 │                             HsmBackedX25519/EcdhKeyEncryptionMethodGenerator, HsmBackedCompositeKemMethodGenerator (ML-KEM+X25519),
 │                             HsmBackedPublicKeyDataDecryptorFactory (Pendants zu allen dreien),
 │                             HsmBackedPGPDataEncryptorBuilder/-DecryptorFactory (CFB via ECB-Blockop & AEAD/GCM),
 │                             HsmBackedPGPContentSignerBuilder/-VerifierBuilder (RSA/ECDSA/EdDSA/ML-DSA über den einen `HsmSignature`-Port) (@InfrastructureServiceAdapter)
 └── module-info.java (@NullMarked)
```

ArchUnit-Testklasse mit den sieben Standardregeln aus `HexagonalArchitectureRules` gemäß CLAUDE.md.

## Abhängigkeiten (zu verifizierende aktuelle Versionen vor dem Schreiben der `pom.xml`)

- `org.bouncycastle:bcpg-jdk18on` (+ ggf. `bcutil-jdk18on`) — **nur** Paketformat/Orchestrierung, keine `BouncyCastleProvider`-Registrierung, kein `Bc*`/`Jce*`-Crypto-Backend für die eigentlichen Operationen. **Vorab prüfen:** unterstützt die aktuelle Version RFC 9980 (Alg-IDs 30/35, komposite Paketstrukturen) bereits auf Paketebene, oder muss das selbst nachgebaut werden?
- Java 25, Spring Boot 4.x, Log4j2, MapStruct (nur falls DTOs für den CLI-Adapter nötig), JSpecify, `ms.rohde:hexagonal-arch-*` (alle drei Module).
- JUnit 5, Mockito, AssertJ, ArchUnit.

## Umsetzungsschritte

1. **spec-writer (forward)** für `docs/features/openpgp-encryption.md` und `docs/features/openpgp-signing.md` — Feature-Spezifikation vor Code, inkl. beider SEIPD-Profile und der ECC-/PQC-Algorithmen (ID 30 & 35).
2. Projektgerüst + **Spike**: Maven-Setup, `module-info.java`, Dockerfile, `docker-compose.yml`, `.gitignore`, README-Grundgerüst; dabei früh klären, ob `bcpg` RFC 9980 auf Paketebene bereits abbildet (siehe Abhängigkeiten-Risiko) — Ergebnis bestimmt, ob Schritt 5 Paket-Handling selbst nachbauen muss.
3. **core-coder**: Domain (`core/domain`) und Use-Case-Orchestrierung (`core/app`) inkl. neuer Outbound-Port-Interfaces `HsmSignature`, `HsmKeyAgreement`, `HsmKeyEncapsulation` (Definition, noch ohne Implementierung) sowie Wiederverwendung/Erweiterung der angenommenen `HsmAesEncryption`/`HsmRsaEncryption`-Signaturen (Cipher-Mode-Setter).
4. **core-coder**: Dummy-Outbound-Adapter (`adapters/outbound/hsm/dummy`) — funktionale Nachbildung aller fünf Hsm-Primitiven auf Basis von Standard-JDK-Crypto bzw. BC-Rohprimitiven (für ML-KEM/ML-DSA), klar dokumentiert als Test-Double für ICSF.
5. **core-coder**: Bouncy-Castle-Bridge-Adapter (`adapters/outbound/openpgp/bc`) — die eigentliche technische Kernarbeit: Implementierung der BC-SPI-Interfaces gegen die Hsm-Ports, für beide SEIPD-Profile, für RSA/ECDSA/EdDSA/ML-DSA-Signaturen sowie RSA/X25519/ML-KEM+X25519-Verschlüsselung.
6. **webmvc-adapter-coder** (falls ein einfacher REST-Endpunkt gewünscht) *oder* schlanker eigener CLI-`@DrivingAdapter` (CommandLineRunner) für die Demo — Entscheidung im Review, tendenziell CLI, da PoC-Fokus auf der Krypto-Bridge liegt, nicht auf einer Web-Fassade.
7. Interop-Tests: Round-Trip über unsere Hsm-Pipeline; zusätzlich Kreuzvalidierung mit **unveränderter** Standard-BC-PGP-Implementierung (bzw. `gpg`, falls lokal verfügbar und PQC-fähig) — verschlüsselt/signiert mit unserer HSM-Bridge, entschlüsselt/verifiziert mit Standard-Tooling und umgekehrt, jeweils für RSA-, ECC- und PQC-Profil. Das ist der zentrale Nachweis der PoC.
8. **arch-reviewer** nach Abschluss aller Schichten.
9. **tech-documenter** für `docs/technical/openpgp-hsm-bridge.md` (BC-SPI-Bridge, beide SEIPD-Profile, Schlüssel-Handle-Modellierung, **und explizit der CCA-Realitätscheck inkl. X25519-Unsicherheit und ML-KEM-Encaps/Decaps-Annahme**).
10. README.md finalisieren (Setup, Konfiguration, Ausführen der Demo, Erklärung "kein JCE/PKCS11", unterstützte Algorithmen).
11. Git: Feature-Branch (`feat/openpgp-core-domain` etc. je Schritt) → PR pro Agent-Scope; erster Commit auf `main` nur mit expliziter Nutzerbestätigung (leeres Repo, Ausnahmefall lt. CLAUDE.md); danach Branch-Protection auf `main` setzen.
12. **JavaDoc**: abweichend vom sonstigen Standard diesmal komplett auf Deutsch (nur für dieses Projekt).

## Verifikation

- `mvn clean install` (Kompilierung ohne Warnings, alle Tests grün, ArchUnit-Regeln grün).
- Gezielte Interop-Tests: von unserer Pipeline erzeugte `.pgp`/`.asc`-Nachrichten müssen von Standard-BC/gpg lesbar sein (und umgekehrt) — jeweils für beide SEIPD-Profile, für RSA/ECC/PQC und für Signatur/Verifikation.
- Kurze manuelle Demo über den CLI-`@DrivingAdapter` (verschlüsseln → entschlüsseln, signieren → verifizieren, je einmal klassisch und einmal PQC) zur Absicherung des End-to-End-Pfads.

## Offene Punkte für spätere Iterationen (bewusst außerhalb dieser PoC)

- HSM-seitige Schlüsselerzeugung (eigener Keygen-Port).
- SHOULD-Varianten der PQC-Kombinationen (ID 31/36, 448er-Kurven) und SLH-DSA (standalone, hash-basiert).
- Verifikation der exakten CCA-Verb-Namen für ML-KEM-Encapsulate/Decapsulate sowie Bestätigung/Widerlegung der X25519-ECDH-Unterstützung gegen die reale ICSF-Callable-Services-Referenz (in dieser PoC nur als dokumentierte Annahme behandelt).
- Echter ICSF-Adapter (bleibt außerhalb dieser PoC — nur Dummy).
