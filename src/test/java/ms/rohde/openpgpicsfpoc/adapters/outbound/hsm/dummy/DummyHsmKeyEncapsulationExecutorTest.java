package ms.rohde.openpgpicsfpoc.adapters.outbound.hsm.dummy;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.security.KeyPairGenerator;
import ms.rohde.openpgpicsfpoc.core.domain.HsmKeyHandle;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmKeyEncapsulation;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmKeyEncapsulationOperation;
import org.junit.jupiter.api.Test;

class DummyHsmKeyEncapsulationExecutorTest {

    @Test
    void execute_givenEncapsulateThenDecapsulate_thenBothSidesDeriveSameSharedSecret() throws Exception {
        var keyStore = new InMemoryHsmKeyStore();
        var handle = new HsmKeyHandle("recipient-mlkem");
        var keyPair = KeyPairGenerator.getInstance("ML-KEM-768").generateKeyPair();
        keyStore.registerKeyPair(handle, keyPair);
        var executor = new DummyHsmKeyEncapsulationExecutor(keyStore);

        var encapsulateResult = executor.execute(HsmKeyEncapsulation.builder()
                .keyHandle(handle)
                .operation(HsmKeyEncapsulationOperation.ENCAPSULATE)
                .build());

        assertThat(encapsulateResult.encapsulatedKey()).isNotNull();

        var decapsulateResult = executor.execute(HsmKeyEncapsulation.builder()
                .keyHandle(handle)
                .operation(HsmKeyEncapsulationOperation.DECAPSULATE)
                .encapsulatedKey(encapsulateResult.encapsulatedKey())
                .build());

        assertThat(decapsulateResult.sharedSecret()).isEqualTo(encapsulateResult.sharedSecret());
        assertThat(decapsulateResult.encapsulatedKey()).isNull();
    }

    @Test
    void execute_givenUnknownHandle_thenThrowsIllegalStateException() {
        var executor = new DummyHsmKeyEncapsulationExecutor(new InMemoryHsmKeyStore());
        var request = HsmKeyEncapsulation.builder()
                .keyHandle(new HsmKeyHandle("unknown"))
                .operation(HsmKeyEncapsulationOperation.ENCAPSULATE)
                .build();

        assertThatThrownBy(() -> executor.execute(request)).isInstanceOf(IllegalStateException.class);
    }
}
