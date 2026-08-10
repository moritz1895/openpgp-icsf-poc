package ms.rohde.openpgpicsfpoc.adapters.inbound.cli;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

import ms.rohde.openpgpicsfpoc.adapters.outbound.hsm.dummy.InMemoryHsmKeyStore;
import ms.rohde.openpgpicsfpoc.core.domain.ByteSequence;
import ms.rohde.openpgpicsfpoc.core.domain.OpenPgpMessage;
import ms.rohde.openpgpicsfpoc.ports.inbound.DecryptOpenPgpMessageUseCase;
import ms.rohde.openpgpicsfpoc.ports.inbound.EncryptOpenPgpMessageUseCase;
import ms.rohde.openpgpicsfpoc.ports.inbound.SignOpenPgpMessageUseCase;
import ms.rohde.openpgpicsfpoc.ports.inbound.VerifyOpenPgpSignatureUseCase;
import org.junit.jupiter.api.Test;

/**
 * Isolierter Verhaltenstest von {@link OpenPgpDemoRunner} gegen gemockte treibende Ports - im
 * Gegensatz zum vollstaendigen Spring-Kontext-Smoke-Test ({@link OpenPgpDemoRunnerSmokeTest})
 * prueft dieser Test gezielt die eigene Erfolgs-/Fehlschlagslogik des Runners (Zusammenfassung,
 * Fehlschlag-Erkennung), nicht das Zusammenspiel der echten Bridge-/Hsm-Kette.
 */
class OpenPgpDemoRunnerTest {

    private static final OpenPgpMessage DUMMY_MESSAGE = new OpenPgpMessage(ByteSequence.of(new byte[] {1}));

    @Test
    void run_givenAllRoundTripsSucceed_thenCompletesWithoutException() {
        var encryptUseCase = mock(EncryptOpenPgpMessageUseCase.class);
        var decryptUseCase = mock(DecryptOpenPgpMessageUseCase.class);
        var signUseCase = mock(SignOpenPgpMessageUseCase.class);
        var verifyUseCase = mock(VerifyOpenPgpSignatureUseCase.class);
        given(encryptUseCase.encrypt(any())).willReturn(DUMMY_MESSAGE);
        given(decryptUseCase.decrypt(any())).willReturn(OpenPgpDemoRunner.DEMO_PLAINTEXT);
        given(signUseCase.sign(any())).willReturn(DUMMY_MESSAGE);
        given(verifyUseCase.verify(any())).willReturn(true);
        var runner = new OpenPgpDemoRunner(
                encryptUseCase, decryptUseCase, signUseCase, verifyUseCase, new InMemoryHsmKeyStore());

        assertThatCode(runner::run).doesNotThrowAnyException();
    }

    @Test
    void run_givenDecryptedPlaintextDiffersFromOriginal_thenThrowsIllegalStateException() {
        var encryptUseCase = mock(EncryptOpenPgpMessageUseCase.class);
        var decryptUseCase = mock(DecryptOpenPgpMessageUseCase.class);
        var signUseCase = mock(SignOpenPgpMessageUseCase.class);
        var verifyUseCase = mock(VerifyOpenPgpSignatureUseCase.class);
        given(encryptUseCase.encrypt(any())).willReturn(DUMMY_MESSAGE);
        given(decryptUseCase.decrypt(any())).willReturn(ByteSequence.of(new byte[] {9, 9, 9}));
        given(signUseCase.sign(any())).willReturn(DUMMY_MESSAGE);
        given(verifyUseCase.verify(any())).willReturn(true);
        var runner = new OpenPgpDemoRunner(
                encryptUseCase, decryptUseCase, signUseCase, verifyUseCase, new InMemoryHsmKeyStore());

        assertThatThrownBy(runner::run).isInstanceOf(IllegalStateException.class);
    }

    @Test
    void run_givenVerificationReturnsInvalid_thenThrowsIllegalStateException() {
        var encryptUseCase = mock(EncryptOpenPgpMessageUseCase.class);
        var decryptUseCase = mock(DecryptOpenPgpMessageUseCase.class);
        var signUseCase = mock(SignOpenPgpMessageUseCase.class);
        var verifyUseCase = mock(VerifyOpenPgpSignatureUseCase.class);
        given(encryptUseCase.encrypt(any())).willReturn(DUMMY_MESSAGE);
        given(decryptUseCase.decrypt(any())).willReturn(OpenPgpDemoRunner.DEMO_PLAINTEXT);
        given(signUseCase.sign(any())).willReturn(DUMMY_MESSAGE);
        given(verifyUseCase.verify(any())).willReturn(false);
        var runner = new OpenPgpDemoRunner(
                encryptUseCase, decryptUseCase, signUseCase, verifyUseCase, new InMemoryHsmKeyStore());

        assertThatThrownBy(runner::run).isInstanceOf(IllegalStateException.class);
    }

    @Test
    void run_givenUseCaseThrows_thenThrowsIllegalStateException() {
        var encryptUseCase = mock(EncryptOpenPgpMessageUseCase.class);
        var decryptUseCase = mock(DecryptOpenPgpMessageUseCase.class);
        var signUseCase = mock(SignOpenPgpMessageUseCase.class);
        var verifyUseCase = mock(VerifyOpenPgpSignatureUseCase.class);
        given(encryptUseCase.encrypt(any())).willThrow(new RuntimeException("HSM nicht erreichbar"));
        var runner = new OpenPgpDemoRunner(
                encryptUseCase, decryptUseCase, signUseCase, verifyUseCase, new InMemoryHsmKeyStore());

        assertThatThrownBy(runner::run).isInstanceOf(IllegalStateException.class);
    }
}
