# openpgp-icsf-poc

PoC: Erweiterung einer proprietären HSM-Krypto-Bibliothek um OpenPGP.

> **Status:** RSA-, natives ECC- (X25519/Ed25519), klassisches ECC-Fallback-Profil (NIST P-256/P-384) sowie die Post-Quantum-Komposit-Verschlüsselung ML-KEM-768+X25519 (RFC 9980, Algorithmus-ID 35) sind implementiert und per CLI-Demo verifiziert; ML-KEM-768+X25519 zusätzlich byte-exakt gegen die RFC-9980-Testvektoren (Appendix A.2) verifiziert, da kein externes Tool für einen Interop-Test verfügbar ist (siehe `docs/technical/openpgp-hsm-bridge.md`, Abschnitt 7.5). Die Post-Quantum-**Signatur** ML-DSA-65+Ed25519 ist **noch nicht implementiert** (erfordert v6-Schlüssel/-Signaturen, siehe „Bekannte Einschränkungen" unten).

## Idee

Es wird angenommen, dass bereits eine hausinterne Krypto-Bibliothek existiert, die kryptographische Bausteine (z. B. JWE) ausschließlich über eine **proprietäre HSM-Primitives-Schnittstelle** bereitstellt — ein generisches Java-Interface nach Builder-Prinzip, das Ausführungsobjekte zusammenbaut und ausführt. Diese Schnittstelle hat **nichts mit JCE oder PKCS#11 zu tun**. Konkreter Backend-Adapter (außerhalb dieser PoC) ist ICSF/CCA auf z/OS mit Crypto-Express-Hardware.

Diese PoC erweitert die Bibliothek um **OpenPGP** (RFC 4880 / RFC 9580 „Crypto-Refresh" / RFC 9980 „Post-Quantum"): Verschlüsseln, Entschlüsseln, Signieren, Verifizieren — für RSA-, natives ECC- (X25519/Ed25519), klassisches ECC-Fallback-Profil (NIST P-256/P-384) und die Post-Quantum-Komposit-Verschlüsselung ML-KEM-768+X25519 — wobei jede kryptographische Operation über die Hsm-Primitives läuft. [Bouncy Castle](https://www.bouncycastle.org/) wird ausschließlich für das OpenPGP-**Paketformat** genutzt, nicht für die eigentlichen Schlüsseloperationen. Die Post-Quantum-**Signatur** (ML-DSA-65+Ed25519) ist als nächster Schritt geplant, aber noch nicht umgesetzt — sie erfordert v6-Schlüssel/-Signaturen, die diese PoC noch nicht modelliert (siehe „Bekannte Einschränkungen").

## Dokumentation — Einstiegspunkte

| Dokument | Für wen / wofür |
|---|---|
| Diese README | Setup, Demo ausführen, aktueller Umsetzungsstand |
| [`docs/technical/production-readiness.md`](docs/technical/production-readiness.md) | **Startpunkt für ein Team, das aus dieser PoC eine produktive Integration bauen will** — was ersetzt werden muss, was übernehmbar bleibt, empfohlene Reihenfolge |
| [`docs/technical/openpgp-hsm-bridge.md`](docs/technical/openpgp-hsm-bridge.md) | Wie die Bouncy-Castle-Bridge im Detail funktioniert (SPI-Extension-Points, Hsm-Ports, SEIPD-Profile, Schlüssel-Handle-Modell) |
| [`docs/technical/pqc-notes.md`](docs/technical/pqc-notes.md) | Was an Post-Quantum-Kryptographie in OpenPGP strukturell besonders ist (komposite Konstruktionen, Key-Combiner, v6-Pflicht, Migrationsaspekte) — unabhängig von dieser konkreten Implementierung |
| [`docs/technical/icsf-cca-gap-analysis.md`](docs/technical/icsf-cca-gap-analysis.md) | Welche benötigten Operationen auf echtem ICSF/CCA belegt sind (mit Verb-Namen: `CSNDDSG`, `CSNDPKE`, `CSNDEDH`, `CSNBSYE`, …) und welche zwei Punkte vor einer echten Anbindung geklärt werden müssen |
| [`docs/features/openpgp-encryption.md`](docs/features/openpgp-encryption.md), [`docs/features/openpgp-signing.md`](docs/features/openpgp-signing.md) | Fachliche Spezifikation (Use Cases, Profile, Fehlerfälle) |
| [`docs/plan.md`](docs/plan.md) | Ursprünglicher Architektur-/Umsetzungsplan (Snapshot, historischer Kontext der Entscheidungen) |

## Setup

```bash
mvn clean install
```

## Ausführen der Demo

```bash
mvn spring-boot:run
```

oder via Docker:

```bash
docker compose up --build
```

## Was macht die Demo?

Der CLI-Demo-Adapter (`OpenPgpDemoRunner`, `adapters/inbound/cli`) läuft beim Start als
Spring-Boot-`CommandLineRunner` einmalig durch und beendet sich danach wieder — kein
Dauerbetrieb, kein HTTP-Port. Er erzeugt lokal frische Demo-Schlüsselpaare (RSA, natives X25519,
klassisches ECDH/ECDSA über P-256, komposites ML-KEM-768+X25519) und registriert sie über den
Dummy-Hsm-Adapter als bereits im (simulierten) HSM vorhanden, da diese PoC keinen
Hsm-Keygen-Port kennt. Anschließend durchläuft er für jede Empfänger-Algorithmus-Kombination
beide SEIPD-Container-Profile (`LEGACY_CFB_MDC`, `AEAD_V2`) je einmal verschlüsseln →
entschlüsseln, sowie für jeden Signaturalgorithmus einmal signieren → verifizieren — insgesamt 11
Durchläufe. Die Post-Quantum-**Signatur** (ML-DSA-65+Ed25519) ist noch nicht implementiert und
daher nicht Teil der Demo. Jeder Durchlauf sowie eine Gesamtzusammenfassung werden über Log4j2
ausgegeben; schlägt auch nur ein Durchlauf fehl, beendet sich der Prozess mit einem Fehler
(Exit-Code ungleich 0).

## Konfiguration

Die Demo benötigt keine externe Konfiguration (keine Umgebungsvariablen, keine Credentials,
kein Netzwerkzugriff). `src/main/resources/application.yml` deaktiviert lediglich den
Spring-Boot-Banner und den Embedded-Web-Server (`web-application-type: none`), da diese PoC
keinen HTTP-Port braucht. Die Log-Ausgabe wird über `src/main/resources/log4j2.xml` gesteuert
(Standard: `INFO` für `ms.rohde.openpgpicsfpoc`, `WARN` für alles andere).

## Bekannte Einschränkungen dieser Iteration

Ausführlich begründet in [`docs/technical/openpgp-hsm-bridge.md`](docs/technical/openpgp-hsm-bridge.md); was das für einen produktiven Einsatz bedeutet, steht gebündelt in [`docs/technical/production-readiness.md`](docs/technical/production-readiness.md):

- **Post-Quantum-Signatur (ML-DSA-65+Ed25519, RFC 9980) nicht implementiert.** Erfordert v6-Schlüssel/-Signaturen (siehe RFC 9980 Section 3.5, sowie [`docs/technical/pqc-notes.md`](docs/technical/pqc-notes.md)), die diese PoC noch nicht modelliert — als eigene Iteration geplant. Die Post-Quantum-**Verschlüsselung** ML-KEM-768+X25519 (Algorithmus-ID 35, mit v4-Schlüsseln zulässig) ist implementiert; `bcpg` 1.85 kennt deren Paketstrukturen zwar ebenfalls nicht, die Bridge umgeht das jedoch selbst (siehe `docs/technical/openpgp-hsm-bridge.md`, Abschnitt 7).
- **EdDSA/Ed25519-Signaturen sind über den digest-basierten `HsmSignature`-Port nicht interoperabel** mit "Pure EdDSA" externer Tools (RSA und ECDSA sind vollständig interop-getestet, Ed25519 rundläuft nur innerhalb dieser Bridge selbst).
- **`EphemeralPeerKeyHandles`/`CompositeMlKemKeyMaterial`** sind Test-Fixture-Workarounds für die fehlende Absenderreferenz beim Entschlüsseln bzw. die Zwei-Handle-Konvention komposit-verschlüsselter Empfänger, keine produktionsreife Lösung.
- **X25519-ECDH- und ML-KEM-Encapsulate/Decapsulate-Unterstützung auf echtem CCA/ICSF sind unbestätigt** — siehe [`docs/technical/icsf-cca-gap-analysis.md`](docs/technical/icsf-cca-gap-analysis.md) für die verb-genaue Aufschlüsselung, was belegt ist und was vor einer echten Anbindung geklärt werden muss.
- Kein Hsm-Keygen-Port — Schlüssel werden als vorab im HSM vorhandene Key-Handles angenommen; die Demo erzeugt ihre Testschlüssel lokal und registriert sie beim Dummy-Hsm-Adapter.
