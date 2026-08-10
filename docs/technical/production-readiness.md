# Von der PoC zur produktiven Nutzung

Dieses Dokument ist der Einstiegspunkt für ein Team, das diese PoC als Ausgangspunkt für eine
echte, produktive Integration gegen ein reales HSM (in der hier angenommenen Zielumgebung: ICSF
auf z/OS über die CCA-Schnittstelle) nehmen will. Es beantwortet die Frage "was genau muss ich
ersetzen/ergänzen, und was kann ich unverändert übernehmen?" — sortiert nach Aufwand und
Risiko, nicht nach Dateireihenfolge.

Ziel dieser PoC war der **Architektur-Nachweis** (proprietäre Hsm-Primitives-Schnittstelle statt
JCE/PKCS11, OpenPGP darüber), nicht ein produktionsreifes Artefakt. Entsprechend sind mehrere
Stellen bewusst vereinfacht — jede davon ist unten einzeln benannt, mit einer konkreten
Handlungsempfehlung statt eines vagen "müsste man noch machen".

## Kurzfassung: was bleibt, was muss weg

| Schicht | Status | Aktion für Produktion |
|---|---|---|
| `core/domain`, `core/app`, `ports/*` | **Stabil, unverändert übernehmbar.** Das ist der eigentliche Wert der Hexagonal-Architektur hier. | Keine. Ports sind die Vertragsgrenze zu einem echten Adapter. |
| `adapters/outbound/openpgp/bc` (Bouncy-Castle-Bridge) | **Größtenteils übernehmbar**, mit Einschränkungen (siehe unten: EdDSA-Interop, Reflection-Nutzung, v6-Lücke). | Punktuell härten, nicht neu bauen. |
| `adapters/outbound/hsm/dummy` | **Muss vollständig ersetzt werden.** Das *ist* der Teil, der heute simuliert, was eine echte ICSF/CCA-Anbindung leisten muss. | Neuer Adapter pro Executor-Port (siehe [`icsf-cca-gap-analysis.md`](icsf-cca-gap-analysis.md)). |
| `adapters/inbound/cli` (Demo) | **Wegwerfcode.** Existiert nur zum Vorführen. | Durch echte(n) treibende(n) Adapter(en) ersetzen (REST, Messaging, Batch — je nach Zielarchitektur), inkl. echter Schlüsselprovisionierung statt `DemoKeyMaterial`. |
| Konfiguration (`application.yml`) | **Praktisch leer.** Diese PoC braucht keine Verbindungsparameter, weil es keine echte Verbindung gibt. | Vollständig neu: ICSF-Verbindungsparameter, Schlüssel-Label-Konventionen, Timeouts, Retry-Policy (siehe „Betriebsaspekte" unten). |

## 1. Die fünf Dummy-Hsm-Adapter ersetzen

`adapters/outbound/hsm/dummy/*` bildet jeden der fünf Hsm-Executor-Ports (`HsmRsaEncryption`,
`HsmAesEncryption`, `HsmSignature`, `HsmKeyAgreement`, `HsmKeyEncapsulation`) über
Standard-JDK-Crypto nach, mit einem simplen In-Memory-Schlüsselspeicher
(`InMemoryHsmKeyStore`). Für Produktion wird pro Port ein `@InfrastructureServiceAdapter`
gebraucht, der denselben Port implementiert, aber die Operation tatsächlich über eine
CCA-Callable-Service-Anbindung (klassisch: `CSNBxxx`/`CSNDxxx`-Aufrufe über die native CCA-API
bzw. deren Java-Wrapper) ausführt.

Der **entscheidende Architektur-Vorteil**: Weil jeder Port bereits als Builder→Request→Executor
geschnitten ist (siehe `docs/technical/openpgp-hsm-bridge.md`, Abschnitt 2), ist die
Request-Struktur bereits so geformt, dass sie ziemlich direkt auf CCA-Verb-Parameter abbildbar
sein sollte (Schlüssel-Handle → CCA-Key-Token/-Label, Algorithmus-Enum → CCA-Rule-Array-Keyword).
Die genaue Verb-Zuordnung, inkl. der Stellen, an denen die öffentliche IBM-Dokumentation eine
Lücke lässt, steht in [`icsf-cca-gap-analysis.md`](icsf-cca-gap-analysis.md) — **das ist der
erste Termin, den ein Team vor Implementierungsbeginn mit einem ICSF/CCA-Systemexperten
braucht**, nicht erst danach.

**Wichtiger Unterschied zur PoC, der bei der Portierung auffallen wird:** `HsmAesEncryptionRequest`
trägt den Sitzungsschlüssel im Klartext (siehe `docs/technical/openpgp-hsm-bridge.md`,
Abschnitt 2, "Schlüsselmaterial-Adressierung"). Das entspricht CCAs "Clear-Key"-Betriebsmodus.
Ein produktiver Adapter kann wahlweise denselben Modus verwenden (Sitzungsschlüssel bleibt
außerhalb des HSM im Klartext im Adressraum der Anwendung — für einen *ephemeren*, pro Nachricht
neu erzeugten Sitzungsschlüssel oft vertretbar) oder auf CCAs "Secure-Key"-Modus umstellen, was
aber eine Änderung an `HsmAesEncryptionRequest` selbst erfordert (Sitzungsschlüssel müsste dann
ebenfalls als `HsmKeyHandle` statt als `ByteSequence` geführt werden — eine bewusste, im
Architektur-Review zu treffende Entscheidung, kein Bugfix).

## 2. Schlüsselverwaltung und -provisionierung

Diese PoC hat **keinen Hsm-Keygen-Port** — eine bewusste Scope-Entscheidung (siehe
`docs/plan.md`). Für Produktion braucht es mindestens:

- Einen echten Prozess, wie Schlüssel im HSM entstehen (CCA `PKA Key Generate`/`CSNDPKG` für
  RSA/ECC/PQC-Schlüssel, siehe Gap-Analyse) und wie deren `HsmKeyHandle`/Label an die
  Anwendungsschicht gelangt (Schlüssel-Provisionierungs-Workflow, i. d. R. außerhalb des
  Laufzeitpfads dieser Bibliothek).
- Einen echten Prozess für **Fremdschlüssel-Import**: Ein OpenPGP-Empfänger-Zertifikat kommt von
  außen (Keyserver, manueller Austausch); dessen öffentlicher Schlüssel muss vor der ersten
  Verschlüsselungs-Operation ins HSM importiert werden (CCA `PKA Key Import`/`CSNDPKI`), damit
  ein `HsmKeyHandle` dafür existiert. Diese PoC umgeht das, indem `InMemoryHsmKeyStore` Schlüssel
  direkt injiziert bekommt (Tests, CLI-Demo) — das ist der wichtigste einzelne Punkt, der beim
  Übergang zur Produktion tatsächlich neuen Code braucht, nicht nur einen neuen Adapter.

## 3. Die Zwei-Handle-Konvention bei ML-KEM-768+X25519 auflösen

`CompositeMlKemKeyMaterial` und `EphemeralPeerKeyHandles` (siehe
`docs/technical/openpgp-hsm-bridge.md`, Abschnitte 5 und 7.4) lösen ein echtes strukturelles
Problem — ein OpenPGP-Komposit-Schlüssel ist *ein* Paket mit *zwei* kryptographischen
Teilschlüsseln, aber `PgpKeyReference` trägt nur einen `HsmKeyHandle` — mit einer
Namenskonvention (`<alias>-x25519`) bzw. einer deterministischen Ableitung aus dem öffentlichen
Punkt (`"ecdh-peer-" + SHA-256(...)`). Beides ist für eine PoC angemessen, aber **keine
produktionsreife Schlüsselverwaltung**: eine Namenskonvention ist kein Vertrag, den ein externes
Schlüsselverwaltungssystem einhält.

Für Produktion: `PgpKeyReference` (oder eine neue, komposit-fähige Variante davon) sollte explizit
zwei `HsmKeyHandle`-Felder tragen können (einen je Teilalgorithmus), statt sich auf
Namensableitung zu verlassen. Das ist eine kleine, gut lokalisierte Domain-Änderung — kein
Neubau.

## 4. Bekannte funktionale Lücken, die vor Produktivbetrieb geschlossen werden müssen

Diese vier Punkte stehen bereits ausführlich in `docs/technical/openpgp-hsm-bridge.md` (Abschnitt
5) und im README — hier nur als Entscheidungs-/Aufwands-Einordnung für die Produktivplanung:

| Lücke | Blockiert Produktivbetrieb für... | Aufwand, um zu schließen |
|---|---|---|
| EdDSA/Ed25519 nicht interoperabel (Digest-basiert statt "Pure EdDSA") | Jeden Ed25519-Signatur-Anwendungsfall, bei dem Gegenstellen unveränderte OpenPGP-Tools nutzen | Mittel: `HsmSignature`/`HsmSignatureExecutor` müsste einen Rohnachrichten-Modus für EdDSA bekommen (Ed25519 signiert intern über die volle Nachricht inkl. eines vorangestellten SHA-512-Präfixes, nicht über einen extern vorberechneten Digest) — echte Protokolländerung am Port, kein reiner Adapter-Fix. |
| ML-DSA-65+Ed25519-Signatur (Alg-ID 30) fehlt komplett | Jeden PQC-Signatur-Anwendungsfall | Groß: erfordert v6-Schlüssel-/Signaturpaket-Unterstützung (neues Fingerprint-Verfahren SHA-256 statt SHA-1, 4-Byte-Längenfeld für Schlüsselmaterial, gesalzene Hash-Berechnung) — siehe `docs/technical/pqc-notes.md`. |
| `PGPSessionKeyEncryptedData`-Konstruktion per Reflection (siehe Abschnitt 7.1 der Bridge-Doku) | Nichts direkt — funktioniert zuverlässig, solange `bcpg` die interne Konstruktor-Signatur nicht ändert | Klein, aber laufende Wartungslast: bei jedem `bcpg`-Versions-Upgrade prüfen, ob der Konstruktor noch existiert (siehe Empfehlung im arch-reviewer-Finding dieser Iteration: einen Testfall/Kommentar ergänzen, der bei einem `bcpg`-Upgrade laut fehlschlägt). Mittelfristig durch native `bcpg`-PQC-Unterstützung ablösbar, sobald verfügbar. |
| X25519-ECDH-Unterstützung auf echtem CCA unbestätigt | Sowohl natives RFC-9580-X25519-Profil als auch die ECDH-Hälfte von ML-KEM-768+X25519 | Kein Code-Aufwand, sondern eine Abklärung: vor Implementierungsbeginn mit einem ICSF/CCA-Systemexperten prüfen (siehe `icsf-cca-gap-analysis.md`). Fällt X25519 aus, ist die dokumentierte Fallback-Strategie, auf klassisches NIST-Kurven-ECDH (P-256/P-384) auszuweichen — dafür ist in dieser PoC bereits alles vorhanden (`PgpPublicKeyAlgorithm.ECDH`). |

## 5. Betriebsaspekte, die diese PoC komplett ausklammert

Eine PoC muss nicht betriebsbereit sein — für Produktion aber fehlt hier mehr als nur "der echte
Adapter":

- **Performance der CFB-über-Einzelblock-Konstruktion (SEIPD v1):** `HsmCfbEngine` ruft für
  *jeden* 16-Byte-Block der Nachricht einen eigenen `HsmAesEncryptionExecutor`-Aufruf auf (siehe
  Bridge-Doku Abschnitt 3.1). Für eine PoC ist das die didaktisch korrekte, direkte Abbildung der
  HSM-Primitive — für eine große Nachricht in Produktion bedeutet das potenziell tausende
  einzelne HSM-Roundtrips (Netzwerk-/Cross-Memory-Latenz pro Call!) statt eines einzigen
  Bulk-Aufrufs. Handlungsoptionen: (a) in Produktion bevorzugt das AEAD/GCM-Profil (SEIPD v2)
  verwenden, das über `HsmAeadChunkCodec` bereits in größeren Chunks (4096 Byte) arbeitet, und
  Legacy-CFB nur für Abwärtskompatibilität mit alten Empfängern vorsehen; (b) prüfen, ob die
  reale CCA-Symmetric-Key-Encipher/Decipher-Verb-Familie einen echten Bulk-CFB-Modus mit
  korrektem 128-Bit-Feedback anbietet, der sich (ohne den OpenPGP-spezifischen Null-IV-Sonderfall
  zu verletzen) direkt für ganze Nachrichten statt Einzelblöcke nutzen ließe.
- **HSM-Erreichbarkeit und Fehlerbehandlung:** Die Dummy-Adapter werfen bei Fehlern
  `HsmDummyOperationException` — ein Platzhalter. Ein echter Adapter muss reale CCA-Rückgabecodes
  (Return/Reason-Codes) auf sinnvolle, für die Anwendungsschicht unterscheidbare Fehlertypen
  abbilden (transient vs. permanent, z. B. HSM temporär nicht erreichbar vs. Schlüssel nicht
  gefunden), inkl. Retry-/Circuit-Breaker-Strategie.
- **Nebenläufigkeit/Verbindungsmanagement:** Diese PoC macht keine Aussage darüber, wie viele
  gleichzeitige CCA-Aufrufe ein produktiver Adapter zulassen darf oder wie eine Verbindung zum
  Crypto-Coprozessor verwaltet wird (Connection-Pooling, Session-Handling) — reiner
  Infrastruktur-Belang des echten Adapters, den die Ports bewusst nicht vorwegnehmen.
- **Konfiguration und Geheimnisverwaltung:** `application.yml` ist aktuell praktisch leer (siehe
  README, Abschnitt „Konfiguration"). Produktiv braucht es mindestens: ICSF-Host-/Domain-Angaben,
  Schlüssel-Label-Namensschema, Timeout-/Retry-Parameter — und die Zusicherung, dass in keiner
  Konfigurationsdatei jemals geheimes Schlüsselmaterial landet (bei korrekter HSM-Nutzung ohnehin
  strukturell ausgeschlossen, da private Schlüssel nie über `HsmKeyHandle` hinaus nach außen
  dringen).
- **Audit/Protokollierung:** Für ein produktives Kryptosystem i. d. R. Pflicht (wer hat wann mit
  welchem Schlüssel welche Operation ausgeführt) — diese PoC protokolliert nur technische
  Debug-Information (Log4j2, `INFO`-Level für Demo-Fortschritt).
- **Teststrategie-Wechsel:** Diese PoC verifiziert gegen Dummy-Adapter (funktional äquivalent,
  aber kein CCA) und — für ML-KEM-768+X25519 — byte-exakt gegen die RFC-9980-Testvektoren (siehe
  Bridge-Doku Abschnitt 7.5). Für Produktion braucht es zusätzlich Kontrakttests gegen eine
  echte oder simulierte ICSF-Umgebung (z. B. eine ICSF-Testinstanz oder ein von IBM bereitgestelltes
  CCA-Simulationswerkzeug, falls verfügbar), da die Dummy-Adapter naturgemäß keine
  CCA-spezifischen Fehlerfälle, Performance-Charakteristika oder Verb-Eigenheiten abbilden können.

## 6. Empfohlene Reihenfolge für ein Produktiv-Team

1. Termin mit ICSF/CCA-Systemexperten: [`icsf-cca-gap-analysis.md`](icsf-cca-gap-analysis.md)
   durchgehen, insbesondere die zwei unbestätigten Punkte (X25519-ECDH, ML-KEM-Encapsulate/
   Decapsulate-Verb) klären.
2. Je nach Ergebnis: Entscheidung treffen, ob natives X25519 (RFC 9580) und ML-KEM-768+X25519
   (RFC 9980) produktiv nutzbar sind, oder ob auf klassisches ECDH (RFC 6637) zurückgefallen
   werden muss.
3. Fünf echte Hsm-Executor-Adapter implementieren (Abschnitt 1), inkl. Fehlerbehandlung/Retry
   (Abschnitt 5).
4. Schlüsselprovisionierung/-import als eigenständigen Workflow bauen (Abschnitt 2).
5. Komposit-Schlüssel-Handle-Modell von der Namenskonvention auf explizite Zwei-Handle-Felder
   umstellen (Abschnitt 3), falls ML-KEM-768+X25519 produktiv genutzt werden soll.
6. Produktiven treibenden Adapter statt `OpenPgpDemoRunner` bauen.
7. EdDSA-Interop-Lücke schließen, falls Ed25519-Signaturen mit externen Gegenstellen
   ausgetauscht werden sollen.
8. v6-Schlüssel-/Signaturpaket-Unterstützung nachziehen, falls ML-DSA-65+Ed25519-Signaturen
   gebraucht werden (siehe `docs/technical/pqc-notes.md`).

`core/domain`, `core/app` und die Port-Interfaces bleiben durch alle acht Schritte hindurch
stabil — das ist der Punkt der Hexagonal-Architektur.
