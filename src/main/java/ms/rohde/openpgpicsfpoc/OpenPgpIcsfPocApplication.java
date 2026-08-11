package ms.rohde.openpgpicsfpoc;

import ms.rohde.hexagonalarch.spring.ArchComponentScan;
import ms.rohde.openpgpicsfpoc.adapters.outbound.hsm.dummy.InMemoryHsmKeyStore;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Spring-Boot-Hauptklasse der OpenPGP-HSM-PoC.
 *
 * <p>Startet den {@link ms.rohde.openpgpicsfpoc.adapters.inbound.cli.OpenPgpDemoRunner}, der beim
 * Start einmalig eine vollstaendige Demo (Verschluesseln/Entschluesseln sowie
 * Signieren/Verifizieren fuer alle in dieser Iteration unterstuetzten Algorithmus-/Profil-
 * Kombinationen) durchlaeuft und sich danach beendet - kein Dauerbetrieb, kein HTTP-Port.</p>
 */
@SpringBootApplication
@Configuration
@ArchComponentScan("ms.rohde.openpgpicsfpoc")
public class OpenPgpIcsfPocApplication {

    public static void main(String[] args) {
        SpringApplication.run(OpenPgpIcsfPocApplication.class, args);
    }

    /**
     * {@link InMemoryHsmKeyStore} ist bewusst kein {@code @InfrastructureServiceAdapter} (sie
     * implementiert selbst keinen Port, sondern wird von mehreren Dummy-Hsm-Adaptern gemeinsam
     * genutzt) und wird daher nicht ueber {@link ArchComponentScan} gefunden - dieser
     * Composition-Root-Bean-Definition macht sie als gemeinsam genutzte Singleton-Instanz fuer
     * alle Dummy-Hsm-Adapter sowie den CLI-Demo-Adapter verfuegbar.
     */
    @Bean
    public InMemoryHsmKeyStore hsmKeyStore() {
        return new InMemoryHsmKeyStore();
    }

    /**
     * {@link BcKeyFingerprintCalculator} ist eine zustandslose Bouncy-Castle-Bibliotheksklasse
     * ohne eigene {@code @InfrastructureServiceAdapter}-Rolle und wurde vor dieser
     * Bean-Definition an zwei Stellen ({@code HsmBackedOpenPgpMessageCodec},
     * {@code PgpKeyMaterialCodec}) redundant als {@code private static final}-Feld
     * instanziiert - dieselbe Art von versteckter, nicht austauschbarer Kopplung, die
     * {@link #hsmKeyStore()} oben fuer {@link InMemoryHsmKeyStore} vermeidet. Diese
     * Composition-Root-Bean-Definition macht sie stattdessen als einzige, injizierte
     * Instanz verfuegbar.
     */
    @Bean
    public BcKeyFingerprintCalculator bcKeyFingerprintCalculator() {
        return new BcKeyFingerprintCalculator();
    }
}
