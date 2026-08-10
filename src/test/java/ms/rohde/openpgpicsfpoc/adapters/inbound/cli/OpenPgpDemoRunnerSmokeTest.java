package ms.rohde.openpgpicsfpoc.adapters.inbound.cli;

import static org.assertj.core.api.Assertions.assertThat;

import ms.rohde.openpgpicsfpoc.OpenPgpIcsfPocApplication;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;

/**
 * Voller Spring-Boot-Kontext-Smoke-Test der CLI-Demo: laedt den gesamten Anwendungskontext mit
 * allen echten Beans - Anwendungsservices, Bouncy-Castle-Bridge-Codec und Dummy-Hsm-Adapter -
 * ohne jegliches Mocking, denn genau diese vollstaendige Verdrahtung ist die Demo selbst.
 *
 * <p>{@link OpenPgpDemoRunner} laeuft als {@code CommandLineRunner} bereits automatisch waehrend
 * des Kontextstarts. Schlaegt darin auch nur ein einziger Verschluesselungs-/Signatur-Durchlauf
 * fehl, wirft {@code run()} eine {@link IllegalStateException} und der Kontextstart - und damit
 * dieser Test - schlaegt fehl. Ein erfolgreich geladener Kontext ist daher bereits der Beweis,
 * dass alle Demo-Durchlaeufe erfolgreich waren.</p>
 */
@SpringBootTest(classes = OpenPgpIcsfPocApplication.class)
class OpenPgpDemoRunnerSmokeTest {

    @Autowired
    private ApplicationContext context;

    @Test
    void contextLoads_givenRealDummyHsmAdaptersWired_thenDemoRunnerCompletesAllRoundTripsSuccessfully() {
        assertThat(context.getBean(OpenPgpDemoRunner.class)).isNotNull();
    }
}
