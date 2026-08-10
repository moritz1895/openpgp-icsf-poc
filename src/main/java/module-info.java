import org.jspecify.annotations.NullMarked;

/**
 * PoC: Erweiterung einer proprietaeren HSM-Krypto-Bibliothek um OpenPGP,
 * ohne JCE/PKCS11 fuer die eigentlichen kryptographischen Operationen.
 *
 * <p>Der Spring-Boot-Jar laeuft immer ueber "java -jar" auf dem Classpath,
 * nie auf dem Module-Path - dieser Modul-Deskriptor dient ausschliesslich
 * der {@code @NullMarked}-Kennzeichnung und der sauberen
 * Kompilierungs-/Sichtbarkeitsgrenze innerhalb dieses Projekts. {@code open},
 * damit reflektionslastige Spring-Mechanismen (Proxys,
 * Konstruktor-Injection, ...) nicht durch starke Kapselung blockiert werden
 * koennten, falls doch einmal auf dem Modulpfad gestartet wird - hat unter
 * "java -jar" keine praktische Wirkung.</p>
 */
@NullMarked
open module ms.rohde.openpgpicsfpoc {
    requires transitive org.jspecify;
    requires transitive jakarta.inject;
    requires transitive ms.rohde.hexagonalarch.annotations;
    requires org.bouncycastle.pg;
    requires org.bouncycastle.util;
    requires org.bouncycastle.provider;
    requires ms.rohde.hexagonalarch.spring;
    requires spring.boot;
    requires spring.boot.autoconfigure;
    requires spring.context;
    requires spring.beans;
    requires org.apache.logging.log4j;

    exports ms.rohde.openpgpicsfpoc.core.domain;
    exports ms.rohde.openpgpicsfpoc.core.app;
    exports ms.rohde.openpgpicsfpoc.ports.inbound;
    exports ms.rohde.openpgpicsfpoc.ports.outbound;
    exports ms.rohde.openpgpicsfpoc.ports.outbound.hsm;
    exports ms.rohde.openpgpicsfpoc.adapters.outbound.hsm.dummy;
    exports ms.rohde.openpgpicsfpoc.adapters.outbound.openpgp.bc;
    // adapters.inbound.cli wird bewusst NICHT exportiert: es ist der Anwendungseinstiegspunkt
    // dieser PoC, kein wiederverwendbares API-Paket - ein Export wuerde ausserdem
    // OpenPgpDemoRunners CommandLineRunner-Implements-Klausel (Typ aus dem automatischen Modul
    // spring.boot) ohne "requires transitive" nach aussen durchreichen (siehe Compiler-Warnung).
}
