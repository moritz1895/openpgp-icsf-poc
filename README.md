# openpgp-icsf-poc

PoC: Erweiterung einer proprietären HSM-Krypto-Bibliothek um OpenPGP.

> **Status:** Im Aufbau. Diese Datei wird nach Abschluss der Implementierung finalisiert (siehe `docs/technical/openpgp-hsm-bridge.md` und die Feature-Specs unter `docs/features/`).

## Idee

Es wird angenommen, dass bereits eine hausinterne Krypto-Bibliothek existiert, die kryptographische Bausteine (z. B. JWE) ausschließlich über eine **proprietäre HSM-Primitives-Schnittstelle** bereitstellt — ein generisches Java-Interface nach Builder-Prinzip, das Ausführungsobjekte zusammenbaut und ausführt. Diese Schnittstelle hat **nichts mit JCE oder PKCS#11 zu tun**. Konkreter Backend-Adapter (außerhalb dieser PoC) ist ICSF/CCA auf z/OS mit Crypto-Express-Hardware.

Diese PoC erweitert die Bibliothek um **OpenPGP** (RFC 4880 / RFC 9580 „Crypto-Refresh" / RFC 9980 Post-Quantum-Erweiterung): Verschlüsseln, Entschlüsseln, Signieren, Verifizieren — für RSA-, native-ECC- (X25519/Ed25519) und Post-Quantum-Profile (ML-KEM-768+X25519, ML-DSA-65+Ed25519) — wobei jede kryptographische Operation über die Hsm-Primitives läuft. [Bouncy Castle](https://www.bouncycastle.org/) wird ausschließlich für das OpenPGP-**Paketformat** genutzt, nicht für die eigentlichen Schlüsseloperationen.

Details und Architektur-Hintergrund: siehe `docs/technical/openpgp-hsm-bridge.md` (folgt).

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
