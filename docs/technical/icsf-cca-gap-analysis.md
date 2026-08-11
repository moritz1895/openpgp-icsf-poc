# ICSF/CCA-Verb-Abdeckung für diese PoC

Dieses Dokument bildet jeden der fünf Hsm-Executor-Ports dieser PoC auf die zugehörige(n)
CCA-Callable-Services (ICSF-"Verben") ab — Stand öffentlich zugänglicher IBM-Dokumentation,
recherchiert 08/2026, bezogen auf aktuelles ICSF/z/OS mit Crypto Express8S (CEX8S) oder neuerer
Hardware. **Diese PoC implementiert und testet nicht gegen echtes ICSF** — die Zuordnung dient
ausschließlich der Realismus-Prüfung der Port-Schnitte und als Ausgangspunkt für ein Team, das
einen echten Adapter baut (siehe `production-readiness.md`). Wo die öffentliche Dokumentation
keine eindeutige Aussage zulässt, ist das explizit als offener Punkt markiert — nicht als
Bestätigung interpretieren.

Die ausführliche Herleitung mit Quellenlinks steht auch in `docs/plan.md`, Abschnitt
"CCA/ICSF-Realitätscheck" — dieses Dokument fasst dieselben Ergebnisse verb-zentriert und
port-zentriert zusammen und ergänzt sie um weitere Verben (PKA Encrypt/Decrypt, EC
Diffie-Hellman), die im ursprünglichen Realitätscheck noch nicht einzeln benannt waren.

## Übersicht je Hsm-Port

| Hsm-Port dieser PoC | Verwendet für | CCA-Verb(e) | Status |
|---|---|---|---|
| `HsmRsaEncryption` | RSA-PKCS#1v1.5-Wrap des Sitzungsschlüssels (PKESK) | **PKA Encrypt** (`CSNDPKE`/`CSNFPKE`) zum Verschlüsseln, **PKA Decrypt** (`CSNDPKD`/`CSNFPKD`) zum Entschlüsseln | ✅ Bestätigt — Standard-CCA-Funktionsumfang |
| `HsmSignature` (RSA/ECDSA/EdDSA) | Digitale Signatur über vorberechneten Digest | **Digital Signature Generate** (`CSNDDSG`/`CSNFDSG`), **Digital Signature Verify** (`CSNDDSV`/`CSNFDSV`) | ✅ Bestätigt — RSA/ECDSA seit jeher, EdDSA (Ed25519/Ed448) explizit ergänzt laut [APAR OA58880](https://www.ibm.com/support/pages/apar/OA58880) |
| `HsmSignature` (ML-DSA-65+Ed25519, Alg-ID 30) | Wie oben, PQC-Anteil | Dieselben Verben, `CRDL-DSA`-Rule-Array-Keyword für den ML-DSA-Anteil | ✅ Verb-Ebene bestätigt (OA58880, [IBM Docs: CRYSTALS-Dilithium](https://www.ibm.com/docs/en/zos/2.5.0?topic=cryptography-crystals-dilithium-digital-signature-algorithm)) — **beachte:** diese PoC signiert bislang nur die ML-DSA-Kernkomponente im Dummy-Adapter, die komposite EdDSA+ML-DSA-Paketkodierung selbst ist noch nicht umgesetzt (siehe `pqc-notes.md`) |
| `HsmKeyAgreement` (klassisch: P-256/P-384) | ECDH-Punktmultiplikation | **EC Diffie-Hellman** (`CSNDEDH`/`CSNFEDH`) | ✅ Bestätigt — Standard-CCA-Funktionsumfang für NIST-/Brainpool-Kurven |
| `HsmKeyAgreement` (nativ: X25519) | ECDH-Punktmultiplikation, Montgomery-Kurve | Vermutlich ebenfalls `CSNDEDH`/`CSNFEDH`, falls die Kurve unterstützt wird | ⚠️ **Unbestätigt** — öffentliche Doku listet für `CSNDEDH` keine Montgomery-Kurven (X25519/X448) explizit; nur EdDSA-*Signatur*-Unterstützung für Edwards-Kurven ist belegt (OA58880), keine Aussage zu Montgomery-Kurven-*Schlüsselvereinbarung*. Siehe „Offene Punkte" unten. |
| `HsmKeyEncapsulation` (ML-KEM-768) | Encapsulate/Decapsulate | Schlüssel-Lebenszyklus über die **PKA-Key-Familie** bestätigt (siehe unten); die eigentliche Encaps/Decaps-**Operation** hat keinen öffentlich dokumentierten, eigenständigen Verbnamen gefunden | ⚠️ **Teilweise unbestätigt** — siehe „Offene Punkte" unten |
| `HsmAesEncryption` (alle vier Cipher-Modi, genutzt: GCM und ECB) | Symmetrische Chunk-Verschlüsselung (SEIPD v2/AEAD), Einzelblock-ECB (AES-Key-Wrap-Baustein) | **Symmetric Key Encipher** (`CSNBSYE`/`CSNESYE`), **Symmetric Key Decipher** (`CSNBSYD`/`CSNESYD`) | ✅ Bestätigt — Rule-Array unterstützt laut öffentlicher Doku u. a. `CBC`, `CBC-CS`, `CFB`, `CFB-LCFB`, `OFB` sowie eine eigene **GCM Processing Rule** für authentisierte Verschlüsselung |

## Schlüssel-Lebenszyklus (nicht Teil dieser PoC, aber Voraussetzung für Produktion)

Diese PoC hat keinen Hsm-Keygen-Port (siehe `docs/plan.md`), daher hier nur zur Vollständigkeit
für ein Produktiv-Team — die PKA-Key-Familie deckt Erzeugung/Import/Verwaltung für **alle**
Algorithmen dieser PoC ab, RSA/ECC wie PQC gleichermaßen:

| Operation | Verb |
|---|---|
| Schlüssel erzeugen | **PKA Key Generate** (`CSNDPKG`/`CSNFPKG`) — laut IBM-Doku explizit erweitert für CRYSTALS-Dilithium/ML-DSA-Schlüssel; für ML-KEM/Kyber ebenfalls über dieselbe Verb-Familie dokumentiert |
| Fremdschlüssel importieren | **PKA Key Import** (`CSNDPKI`/`CSNFPKI`) |
| Schlüssel-Token bauen (aus Rohmaterial) | **PKA Key Token Build** (`CSNDPKB`/`CSNFPKB`) |
| Schlüssel-Token ändern | **PKA Key Token Change** (`CSNDKTC`/`CSNFKTC`) |
| Schlüssel exportieren/übersetzen (inkl. EC/ML-DSA/ML-KEM) | **PKA Key Translate** (`CSNDPKT`/`CSNFPKT`) |
| Öffentlichen Schlüssel extrahieren | **PKA Public Key Extract** (`CSNDPKX`/`CSNFPKX`) |

Quelle: [IBM Docs: Support for Crypto Express8 adapters, Kyber keys, new key sizes, Dilithium Digital Signature Algorithm](https://www.ibm.com/docs/en/zos/2.5.0?topic=icsf-support-crypto-express8-adapters-kyber-keys-new-key-sizes-dilithium-digital-signature-algorithm),
[APAR OA58880](https://www.ibm.com/support/pages/apar/OA58880). Für ML-KEM/ML-DSA-Schlüssel ist
laut dieser Quelle ein **AES-Transportschlüssel** für Import/Export erforderlich — eine
zusätzliche operative Voraussetzung, die bei klassischen RSA-/EC-Schlüsseln in dieser Form nicht
existiert.

## Offene Punkte — vor Produktivbeginn zu klären

Diese zwei Punkte sind die einzigen echten Unsicherheiten in der obigen Tabelle. Beide sollten
**vor** Beginn einer produktiven Implementierung mit einem ICSF/CCA-Systemexperten bzw. anhand
der aktuellen (nicht öffentlich vollständig zugänglichen) ICSF Callable Services Reference
geklärt werden — diese PoC trifft dazu bewusst keine Annahme, sondern hält die betroffenen Ports
absichtlich algorithmus-/kurvenagnostisch, damit ein echter Adapter ohne Portänderung reagieren
kann:

1. **Unterstützt `CSNDEDH` (EC Diffie-Hellman) X25519/X448?** Öffentliche CCA-Dokumentation
   listet Kurvenunterstützung meist für NIST- (P-256/P-384/P-521) und Brainpool-Kurven; eine
   explizite Erwähnung von Montgomery-Kurven (X25519/X448) für die *Schlüsselvereinbarung* wurde
   nicht gefunden — im Unterschied zur *Signatur*-Seite, wo Edwards-Kurven (Ed25519/Ed448, für
   EdDSA) explizit als CCA-Erweiterung dokumentiert sind (OA58880). Das sind kryptographisch
   verwandte, aber verbtechnisch unterschiedliche Kurvenfamilien (Montgomery vs. Edwards) —
   EdDSA-Unterstützung ist **kein** Beleg für X25519-ECDH-Unterstützung. **Auswirkung, falls
   nicht unterstützt:** sowohl das native RFC-9580-X25519-Verschlüsselungsprofil als auch die
   ECDH-Hälfte von ML-KEM-768+X25519 (RFC 9980, Alg-ID 35) müssten auf klassisches
   NIST-Kurven-ECDH (P-256/P-384) ausweichen — dafür ist in dieser PoC mit
   `PgpPublicKeyAlgorithm.ECDH` bereits alles vorhanden.
2. **Gibt es ein dediziertes CCA-Verb für ML-KEM-Encapsulate/Decapsulate, oder läuft das über
   eine bestehende Verb-Familie (z. B. als neue Rule-Array-Option von `CSNDPKE`/`CSNDPKD`,
   analog zur RSA-Verschlüsselung)?** Der Schlüssel-*Lebenszyklus* (Erzeugen/Importieren/
   Exportieren) ist für ML-KEM/Kyber-Schlüssel eindeutig belegt (siehe Tabelle oben); die
   eigentliche kryptographische *Operation* (Encapsulate liefert Chiffretext + Shared Secret,
   Decapsulate liefert Shared Secret aus Chiffretext) wurde in der öffentlich zugänglichen
   Dokumentation nicht mit einem eigenen Verbnamen gefunden. Das kann bedeuten, dass (a) der
   Verbname schlicht nicht in den durchsuchten öffentlichen Quellen auftaucht, (b) die Operation
   über eine bestehende Verb-Familie mit neuem Rule-Array-Keyword abgebildet wird, oder (c) die
   Funktion zum RechercheZeitpunkt noch nicht in dieser Form freigegeben war. **Auswirkung:** Der
   Port `HsmKeyEncapsulation` bleibt in dieser PoC bewusst schlank und algorithmusagnostisch
   gehalten, damit er unabhängig vom Ergebnis dieser Klärung anschlussfähig bleibt.

## Nicht recherchiert (bewusst außerhalb des Scopes dieser PoC)

- SLH-DSA-Verb-Unterstützung (PoC implementiert SLH-DSA nicht, siehe `pqc-notes.md`).
- ML-KEM-1024+X448 bzw. ML-DSA-87+Ed448 (die "SHOULD"-Varianten der RFC-9980-Algorithmen,
  größere Parametersätze — siehe `docs/plan.md`, "Offene Punkte").
- Detaillierte Access-Control-Point-Konfiguration (welche CCA-Rolle welches Verb ausführen darf)
  — reiner Betriebsbelang, nicht Teil des architektonischen Nachweises dieser PoC.
