import org.jspecify.annotations.NullMarked;

/**
 * PoC: Erweiterung einer proprietaeren HSM-Krypto-Bibliothek um OpenPGP,
 * ohne JCE/PKCS11 fuer die eigentlichen kryptographischen Operationen.
 *
 * <p>Der Spring-Boot-Jar laeuft immer ueber "java -jar" auf dem Classpath,
 * nie auf dem Module-Path - dieser Modul-Deskriptor dient ausschliesslich
 * der {@code @NullMarked}-Kennzeichnung und der sauberen
 * Kompilierungs-/Sichtbarkeitsgrenze innerhalb dieses Projekts.</p>
 */
@NullMarked
module ms.rohde.openpgpicsfpoc {
    requires transitive org.jspecify;
    requires transitive jakarta.inject;
    requires transitive ms.rohde.hexagonalarch.annotations;

    exports ms.rohde.openpgpicsfpoc.core.domain;
    exports ms.rohde.openpgpicsfpoc.core.app;
    exports ms.rohde.openpgpicsfpoc.ports.inbound;
    exports ms.rohde.openpgpicsfpoc.ports.outbound;
    exports ms.rohde.openpgpicsfpoc.ports.outbound.hsm;
    exports ms.rohde.openpgpicsfpoc.adapters.outbound.hsm.dummy;
}
