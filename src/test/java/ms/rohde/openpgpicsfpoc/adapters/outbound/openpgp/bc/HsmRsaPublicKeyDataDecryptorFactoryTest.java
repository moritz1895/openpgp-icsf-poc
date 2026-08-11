package ms.rohde.openpgpicsfpoc.adapters.outbound.openpgp.bc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.then;

import ms.rohde.openpgpicsfpoc.core.domain.ByteSequence;
import ms.rohde.openpgpicsfpoc.core.domain.HsmKeyHandle;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmAesEncryptionExecutor;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmCipherOperation;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmRsaEncryptionExecutor;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmRsaEncryptionRequest;
import ms.rohde.openpgpicsfpoc.ports.outbound.hsm.HsmRsaEncryptionResult;
import org.bouncycastle.openpgp.PGPException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class HsmRsaPublicKeyDataDecryptorFactoryTest {

    @Mock
    private HsmRsaEncryptionExecutor rsaExecutor;

    @Mock
    private HsmAesEncryptionExecutor aesExecutor;

    private HsmKeyHandle recipientKeyHandle;
    private HsmRsaPublicKeyDataDecryptorFactory factory;

    @BeforeEach
    void setUp() {
        recipientKeyHandle = new HsmKeyHandle("recipient-rsa");
        factory = new HsmRsaPublicKeyDataDecryptorFactory(rsaExecutor, aesExecutor, recipientKeyHandle);
    }

    @Test
    void recoverSessionData_givenMpiEncodedCiphertext_thenStripsTwoByteHeaderBeforeCallingHsm() {
        byte[] ciphertext = {10, 11, 12, 13};
        byte[] mpiEncoded = new byte[2 + ciphertext.length];
        mpiEncoded[0] = 0x00;
        mpiEncoded[1] = 0x20;
        System.arraycopy(ciphertext, 0, mpiEncoded, 2, ciphertext.length);
        given(rsaExecutor.execute(any())).willReturn(new HsmRsaEncryptionResult(ByteSequence.of(new byte[] {1, 2, 3})));

        byte[] result = factory.recoverSessionData(1, new byte[][] {mpiEncoded}, 3);

        assertThat(result).isEqualTo(new byte[] {1, 2, 3});
        ArgumentCaptor<HsmRsaEncryptionRequest> captor = ArgumentCaptor.forClass(HsmRsaEncryptionRequest.class);
        then(rsaExecutor).should().execute(captor.capture());
        assertThat(captor.getValue().keyHandle()).isEqualTo(recipientKeyHandle);
        assertThat(captor.getValue().operation()).isEqualTo(HsmCipherOperation.DECRYPT);
        assertThat(captor.getValue().input().value()).isEqualTo(ciphertext);
    }

    @Test
    void recoverSessionData_givenHsmRejection_thenThrowsOpenPgpDecryptionFailedException() {
        byte[] mpiEncoded = {0x00, 0x08, 1, 2};
        given(rsaExecutor.execute(any())).willThrow(new RuntimeException("HSM abgelehnt"));

        assertThatThrownBy(() -> factory.recoverSessionData(1, new byte[][] {mpiEncoded}, 3))
                .isInstanceOf(OpenPgpDecryptionFailedException.class);
    }

    @Test
    void createDataDecryptor_givenLegacySeipdV1Request_thenThrowsPGPException() {
        assertThatThrownBy(() -> factory.createDataDecryptor(true, 9, new byte[] {1, 2, 3}))
                .isInstanceOf(PGPException.class);
    }
}
