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

## Konfiguration

*(wird ergänzt, sobald der CLI-Demo-Adapter steht)*
