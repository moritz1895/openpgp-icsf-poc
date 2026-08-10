# openpgp-icsf-poc

PoC: Erweiterung einer proprietären HSM-Krypto-Bibliothek um OpenPGP.

> **Status:** RSA-, natives ECC- (X25519/Ed25519) und klassisches ECC-Fallback-Profil (NIST P-256/P-384) sind implementiert und per CLI-Demo sowie Interop-Tests gegen unveränderte Bouncy Castle verifiziert. Post-Quantum (ML-KEM-768+X25519, ML-DSA-65+Ed25519, RFC 9980) ist **noch nicht implementiert** — siehe „Bekannte Einschränkungen" unten und `docs/technical/openpgp-hsm-bridge.md`.

## Idee

Es wird angenommen, dass bereits eine hausinterne Krypto-Bibliothek existiert, die kryptographische Bausteine (z. B. JWE) ausschließlich über eine **proprietäre HSM-Primitives-Schnittstelle** bereitstellt — ein generisches Java-Interface nach Builder-Prinzip, das Ausführungsobjekte zusammenbaut und ausführt. Diese Schnittstelle hat **nichts mit JCE oder PKCS#11 zu tun**. Konkreter Backend-Adapter (außerhalb dieser PoC) ist ICSF/CCA auf z/OS mit Crypto-Express-Hardware.

Diese PoC erweitert die Bibliothek um **OpenPGP** (RFC 4880 / RFC 9580 „Crypto-Refresh"): Verschlüsseln, Entschlüsseln, Signieren, Verifizieren — für RSA-, natives ECC- (X25519/Ed25519) und klassisches ECC-Fallback-Profil (NIST P-256/P-384) — wobei jede kryptographische Operation über die Hsm-Primitives läuft. [Bouncy Castle](https://www.bouncycastle.org/) wird ausschließlich für das OpenPGP-**Paketformat** genutzt, nicht für die eigentlichen Schlüsseloperationen. Die Post-Quantum-Erweiterung (RFC 9980: ML-KEM-768+X25519, ML-DSA-65+Ed25519) ist als nächster Schritt geplant, aber noch nicht umgesetzt (siehe „Bekannte Einschränkungen").

Details und Architektur-Hintergrund: siehe [`docs/technical/openpgp-hsm-bridge.md`](docs/technical/openpgp-hsm-bridge.md). Fachliche Spezifikation: [`docs/features/openpgp-encryption.md`](docs/features/openpgp-encryption.md), [`docs/features/openpgp-signing.md`](docs/features/openpgp-signing.md). Architektur-Plan (inkl. CCA/ICSF-Realitätscheck, ECC/PQC-Scope): [`docs/plan.md`](docs/plan.md).

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
klassisches ECDH/ECDSA über P-256) und registriert sie über den Dummy-Hsm-Adapter als bereits
im (simulierten) HSM vorhanden, da diese PoC keinen Hsm-Keygen-Port kennt. Anschließend
durchläuft er für jede Empfänger-Algorithmus-Kombination beide SEIPD-Container-Profile
(`LEGACY_CFB_MDC`, `AEAD_V2`) je einmal verschlüsseln → entschlüsseln, sowie für jeden
Signaturalgorithmus einmal signieren → verifizieren — insgesamt 9 Durchläufe. Post-Quantum
(ML-KEM-768+X25519, ML-DSA-65+Ed25519) ist noch nicht implementiert und daher nicht Teil der
Demo. Jeder Durchlauf sowie eine Gesamtzusammenfassung werden über Log4j2 ausgegeben; schlägt
auch nur ein Durchlauf fehl, beendet sich der Prozess mit einem Fehler (Exit-Code ungleich 0).

## Konfiguration

Die Demo benötigt keine externe Konfiguration (keine Umgebungsvariablen, keine Credentials,
kein Netzwerkzugriff). `src/main/resources/application.yml` deaktiviert lediglich den
Spring-Boot-Banner und den Embedded-Web-Server (`web-application-type: none`), da diese PoC
keinen HTTP-Port braucht. Die Log-Ausgabe wird über `src/main/resources/log4j2.xml` gesteuert
(Standard: `INFO` für `ms.rohde.openpgpicsfpoc`, `WARN` für alles andere).

## Bekannte Einschränkungen dieser Iteration

Ausführlich begründet in [`docs/technical/openpgp-hsm-bridge.md`](docs/technical/openpgp-hsm-bridge.md):

- **Post-Quantum (RFC 9980) nicht implementiert.** `bcpg` 1.85 kennt die komposite Paketstrukturen (ML-KEM-768+X25519, ML-DSA-65+Ed25519) noch nicht — das erfordert eigenständig nachgebaute Paketformate und ist als eigene Iteration geplant.
- **EdDSA/Ed25519-Signaturen sind über den digest-basierten `HsmSignature`-Port nicht interoperabel** mit "Pure EdDSA" externer Tools (RSA und ECDSA sind vollständig interop-getestet, Ed25519 rundläuft nur innerhalb dieser Bridge selbst).
- **`EphemeralPeerKeyHandles`** ist ein Test-Fixture-Workaround für die fehlende Absenderreferenz beim Entschlüsseln (`OpenPgpDecryptionRequest`), keine produktionsreife Lösung.
- **X25519-ECDH-Unterstützung auf echtem CCA/ICSF ist unbestätigt** (siehe `docs/plan.md`, Abschnitt „CCA/ICSF-Realitätscheck") — öffentliche IBM-Dokumentation belegt nur EdDSA-Signaturen und klassisches NIST-Kurven-ECDH. Ein echter ICSF-Adapter müsste das vorab klären und ggf. auf klassisches ECDH (RFC 6637) ausweichen.
- Kein Hsm-Keygen-Port — Schlüssel werden als vorab im HSM vorhandene Key-Handles angenommen; die Demo erzeugt ihre Testschlüssel lokal und registriert sie beim Dummy-Hsm-Adapter.
