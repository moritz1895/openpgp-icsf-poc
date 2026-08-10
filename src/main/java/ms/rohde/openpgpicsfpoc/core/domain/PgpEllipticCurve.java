package ms.rohde.openpgpicsfpoc.core.domain;

import ms.rohde.hexagonalarch.annotations.DomainValueObject;

/**
 * Von einem ECDH-faehigen {@link PgpPublicKey} referenzierte elliptische
 * Kurve.
 *
 * <p>Domain-eigenes Gegenstueck zur Hsm-Primitiven-Kurve
 * ({@code ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmEllipticCurve}):
 * {@link #X25519} deckt das native RFC-9580-Profil ab, {@link #P256}/
 * {@link #P384} das klassische ECDH-Fallback-Profil nach RFC 6637 (siehe
 * CCA-Realitaetscheck im Projektplan zur unsicheren X25519-Unterstuetzung
 * auf realer CCA-Hardware). Nur {@link PgpPublicKeyAlgorithm#ECDH} traegt
 * diese Kurve als explizites Attribut - {@link PgpPublicKeyAlgorithm#X25519}
 * hat die Kurve bereits fest ueber den Algorithmus selbst festgelegt (RFC
 * 9580 kodiert X25519 als eigene Algorithmus-ID ohne separaten
 * Kurven-Parameter).</p>
 */
@DomainValueObject
public enum PgpEllipticCurve {
    X25519,
    P256,
    P384
}
