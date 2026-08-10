# Post-Quantum-Kryptographie in OpenPGP: Besonderheiten

Dieses Dokument fasst zusammen, was an Post-Quantum-Kryptographie (PQC) in OpenPGP strukturell
anders ist als "ein paar neue Algorithmus-IDs hinzufügen" — als Hintergrundwissen für jeden, der
mit RFC 9980 arbeitet, unabhängig von dieser konkreten PoC. Die projektspezifische Umsetzung
(welche Klassen was tun) steht in `docs/technical/openpgp-hsm-bridge.md`, Abschnitt 7.

Quelle für alle Aussagen in diesem Dokument: [RFC 9980](https://www.rfc-editor.org/rfc/rfc9980.html)
("Post-Quantum Cryptography in OpenPGP", Juni 2026, erweitert RFC 9580).

## 1. Komposit statt Standalone — mit einer Ausnahme

RFC 9980 definiert **keine** reinen Post-Quantum-Verschlüsselungs- oder
ML-DSA-Signaturverfahren. Stattdessen:

- **ML-KEM** (Verschlüsselung) wird ausschließlich in **kompositer Kombination** mit einem
  klassischen ECDH-KEM (X25519 oder X448) definiert — als bewusster
  Pre-Quantum-Sicherheits-Fallback: Sollte sich herausstellen, dass ML-KEM einen unbekannten
  klassischen Schwachpunkt hat, bleibt die Verschlüsselung durch die ECDH-Komponente trotzdem
  sicher (RFC 9980 Section 1.2.1).
- **ML-DSA** (Signatur) wird ausschließlich in kompositer Kombination mit **EdDSA** definiert,
  aus demselben Grund (Section 1.2.2).
- **SLH-DSA** ist die einzige **standalone** Ausnahme — als hash-basiertes Verfahren gilt es als
  so vertrauenswürdig, dass RFC 9980 es ohne klassischen Kombinationspartner definiert
  (Section 1.2.3). SLH-DSA ist in dieser PoC **nicht** implementiert.

Bei einer kompositen Operation **müssen beide Komponenten erfolgreich sein** — bei
Verschlüsselung müssen beide KEM-Decapsulierungen gelingen, bei Signaturen müssen beide
Signaturen unabhängig valide sein (Section 1.4.1, 3.1, 3.2). Es gibt keinen "eine Komponente
reicht"-Modus für eine komposite Operation — das unterscheidet die komposite Konstruktion vom
in OpenPGP ebenfalls möglichen, aber *nicht* kompositen Fall mehrerer paralleler PKESK-Pakete
bzw. mehrerer unabhängiger Signaturpakete (Section 1.4.2, siehe Punkt 6 unten).

## 2. Der Key-Combiner: nicht einfach XOR oder Konkatenation

Für die ML-KEM+ECDH-Verschlüsselung schreibt RFC 9980 Section 4.2.1 exakt eine Formel vor:

```
KEK = SHA3-256(
    mlkemKeyShare || ecdhKeyShare ||
    ecdhCipherText || ecdhPublicKey ||
    algId || domSep || len(domSep)
)
```

mit `domSep = "OpenPGPCompositeKDFv1"` (UTF-8, 21 Oktette). Bemerkenswert:

- **Beide Chiffretexte/Shared-Secrets fließen ein, plus der öffentliche ECDH-Schlüssel selbst.**
  Das ist kein Zufall: Section 9.2 begründet, dass die Einbeziehung des ECDH-Public-Keys auch
  Multi-Target-Angriffe gegen X25519/X448 abdeckt.
- **`algId` bindet den KEK an den konkreten Algorithmus.** Ein für Alg-ID 35 berechneter KEK ist
  für Alg-ID 36 nicht gültig, selbst bei identischen Rohschlüsseln.
- **`domSep || len(domSep)` ist bewusst "suffix-frei" konstruiert** (Section 9.2.1): Das
  Längen-Oktett am Ende garantiert, dass kein zukünftig definierter `domSep`-Wert als Suffix
  eines anderen erscheinen kann — verhindert Kollisionen zwischen verschiedenen zukünftigen
  Verwendungszwecken desselben Kombinierer-Musters.
- **Sicherheitsbegründung:** Der Kombinierer ist IND-CCA2-sicher, sofern *entweder* ML-KEM
  IND-CCA2-sicher ist *oder* das Strong-Diffie-Hellman-Problem in der jeweiligen Gruppe gilt
  (Section 9.2, mit Verweis auf die zugrundeliegende QSF/X-Wing-Konstruktion). Genau das ist der
  Kern des "Pre-Quantum-Fallback"-Arguments aus Punkt 1: selbst wenn eine der beiden Annahmen
  bricht, bleibt die andere tragend.

Der abgeleitete KEK verpackt den eigentlichen Sitzungsschlüssel per RFC-3394-AES-256-Key-Wrap
(inkl. eingebauter 64-Bit-Integritätsprüfung) — kein neues Verfahren, sondern Wiederverwendung
eines etablierten Bausteins.

## 3. v6 ist für Signaturen Pflicht, für ML-KEM+X25519 optional

RFC 9980 Section 3.5 (Key Version Binding) trifft eine unerwartet asymmetrische Aussage:

- **Alle** PQC-Algorithmen sind auf **v6-Schlüssel/-Zertifikate** beschränkt — **mit genau einer
  Ausnahme**: ML-KEM-768+X25519 (Alg-ID 35) darf zusätzlich in **v4-Verschlüsselungs-Subkeys**
  verwendet werden.
- Die **Signatur**-Algorithmen (ML-DSA-65+Ed25519, SLH-DSA-Varianten) haben **keine** solche
  Ausnahme — sie erfordern immer v6-Schlüssel **und** v6-Signaturpakete.

Der Grund für die v6-Pflicht bei Signaturen ist sicherheitsrelevant, nicht willkürlich
(Section 9.1, 9.4): v6-Signaturpakete enthalten laut RFC 9580 einen führenden **zufälligen Salt**
in den gehashten Metadaten. Ohne diesen Salt wäre eine komposite Signatur theoretisch anfällig
für "Remixing"-Angriffe (Komponenten aus zwei legitimen Signaturen desselben Schlüssels neu
kombinieren) — mit Salt hat jede Signatur eindeutig unterschiedliche gehashte Eingabedaten, was
das für die Sicherheitsargumentation nötige Preimage- statt Kollisionsresistenz-Niveau
herstellt, selbst bei einem "nur" 256-Bit-Hash (siehe Punkt 4).

**Praktische Konsequenz für jede Implementierung, die von einer v4-only-Codebasis startet** (wie
diese PoC): Verschlüsselung mit ML-KEM-768+X25519 lässt sich ohne v6-Unterstützung umsetzen —
Signatur mit ML-DSA-65+Ed25519 nicht. Das ist der Grund, warum diese PoC die beiden Verfahren in
getrennten Iterationen umsetzt (siehe `docs/technical/openpgp-hsm-bridge.md`, Abschnitt 5).

## 4. Mindest-Digest-Größe für PQ(/T)-Signaturen

RFC 9980 Section 5.3.1/9.4 schreibt vor: jede komposite ML-DSA+EdDSA-Signatur **muss** einen
Hash-Algorithmus mit mindestens 256 Bit Digest-Größe verwenden; eine verifizierende Implementierung
**muss** Signaturen mit kleinerem Digest ablehnen. Begründung: Weil v6-Signaturen ohnehin einen
Salt einbetten (Punkt 3), reicht (Second-)Preimage-Resistenz statt Kollisionsresistenz — ein
256-Bit-Hash ist dafür ausreichend, um das Sicherheitsniveau aller in RFC 9980 definierten
PQ(/T)-Algorithmen zu erreichen.

## 5. Hedged-Varianten: Zufall als Seitenkanalschutz, nicht als Signatur-Nichtdeterminismus

ML-DSA und SLH-DSA werden in ihrer **"hedged"**-Standardvariante verwendet (Section 9.3) — sie
mischen bei jeder Signaturerzeugung frische Zufälligkeit in den internen Hashing-Schritt.
Anders als bei klassischem ECDSA (wo Nonce-Wiederverwendung ein bekanntes, kritisches
Sicherheitsproblem ist) dient das hier primär der **Seitenkanal-Resistenz**, nicht der
Verhinderung eines Angriffs bei Nonce-Kollision. Praktisch bedeutet das: zwei Signaturen
derselben Nachricht mit demselben Schlüssel sehen unterschiedlich aus — das ist normal und kein
Implementierungsfehler.

## 6. Migrationsaspekte: Übergangszeit mit gemischten Empfängern/Signaturen

RFC 9980 Section 8 behandelt explizit die Übergangsphase, in der nicht alle Gegenstellen bereits
PQC unterstützen:

- **Verschlüsseln:** Eine Implementierung darf standardmäßig an **sowohl** einen PQ(/T)- als
  auch einen traditionellen Schlüssel desselben Empfängers verschlüsseln (mehrere
  PKESK-Pakete) — das ist der nicht-komposite Multi-Algorithmus-Fall aus Section 1.4.2. Wichtig:
  die Vertraulichkeit der Nachricht ist dabei **nur so stark wie das schwächste** der
  verwendeten Verfahren, solange nicht alle verwendeten Schlüssel PQ(/T)-fähig sind.
- **Signieren:** Eine Nachricht darf mit einem PQ(/T)- **und** einem traditionellen Schlüssel
  gleichzeitig signiert werden (mehrere Signaturpakete) — das sichert Abwärtskompatibilität zu
  Alt-Implementierungen, die nur die traditionelle Signatur prüfen können. Reines
  PQ(/T)-Signieren ist **nicht** abwärtskompatibel.
- **Verifizieren:** Eine Implementierung darf traditionelle Signaturen ignorieren, wenn sie
  gegenüber einem Angreifer mit kryptographisch relevantem Quantencomputer misstrauisch ist —
  das ist eine bewusste Design-Entscheidung der jeweiligen Anwendung, kein RFC-Zwang.
- **Signature-Stripping ist trotz Mehrfachsignaturen kein Problem** (Section 9.1): Da jede
  OpenPGP-Signatur die Algorithmus-ID in den gehashten Metadaten trägt, ist eine aus dem
  kompositen Kontext herausgelöste Einzelkomponente keine für sich gültige OpenPGP-Signatur —
  ein Angreifer kann also nicht einfach die PQC-Hälfte entfernen und die klassische Hälfte als
  eigenständig gültig ausgeben.
- **Bei der Schlüsselerzeugung:** Section 8.4/9.6 empfehlen ausdrücklich, für PQ(/T)-Schlüssel
  frisches Schlüsselmaterial zu erzeugen, statt vorhandenes ECC-Schlüsselmaterial
  wiederzuverwenden — Wiederverwendung stellt keine Abwärtskompatibilität her und kann zu
  Signatur-Confusion-Schwachstellen führen (dasselbe Schlüsselmaterial in zwei Kontexten).

## 7. Praktische Tooling-Reifegrad-Konsequenz (Stand dieser PoC, 08/2026)

`bcpg-jdk18on` 1.85 (die zum Zeitpunkt dieser PoC aktuellste Bouncy-Castle-Version) enthält
**keine** eigenen Paket-/Schlüsselklassen für die RFC-9980-Algorithmus-IDs — weder für ML-KEM
noch für ML-DSA/SLH-DSA. Jede heutige Implementierung von RFC 9980 auf Basis von Bouncy Castle
muss die Paket-Byte-Layouts (Abschnitte 4.3/5.3/6.2 des RFC) selbst nachbauen, statt sie über
BCs High-Level-API zu bekommen — siehe `docs/technical/openpgp-hsm-bridge.md`, Abschnitt 7.1,
für die konkreten Umgehungen, die diese PoC dafür braucht (u. a. Reflection-Zugriff auf einen
package-privaten BC-Konstruktor). Das ist keine Design-Entscheidung dieser PoC, sondern eine
Momentaufnahme des Bibliotheks-Reifegrads — bei einem künftigen `bcpg`-Upgrade mit nativer
RFC-9980-Unterstützung sollten diese Umgehungen durch die dann verfügbare BC-eigene API ersetzt
werden.

Ebenfalls bemerkenswert: **Java selbst** (JDK 24+, JEP 496/497) unterstützt ML-KEM und ML-DSA
bereits nativ über `javax.crypto.KEM` und `java.security.Signature`/`KeyPairGenerator` — nur die
*OpenPGP-Paketkodierung* dieser Algorithmen fehlt in der Bibliothekslandschaft, nicht die
zugrundeliegenden kryptographischen Primitiven selbst. Diese PoC nutzt genau diesen Umstand: der
Dummy-Hsm-Adapter für ML-KEM-768 (`DummyHsmKeyEncapsulationExecutor`) kommt komplett ohne
BC-Abhängigkeit aus.
