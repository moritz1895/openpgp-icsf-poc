package ms.rohde.openpgpicsfpoc.core.domain;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

class PgpPublicKeyAlgorithmTest {

    @ParameterizedTest
    @EnumSource(value = PgpPublicKeyAlgorithm.class, names = {"RSA", "X25519", "ECDH", "ML_KEM_768_X25519"})
    void supportsEncryption_givenEncryptionAlgorithm_thenReturnsTrue(PgpPublicKeyAlgorithm algorithm) {
        assertThat(algorithm.supportsEncryption()).isTrue();
    }

    @ParameterizedTest
    @EnumSource(value = PgpPublicKeyAlgorithm.class, names = {"ECDSA", "EDDSA", "ML_DSA_65_ED25519"})
    void supportsEncryption_givenSignatureOnlyAlgorithm_thenReturnsFalse(PgpPublicKeyAlgorithm algorithm) {
        assertThat(algorithm.supportsEncryption()).isFalse();
    }

    @ParameterizedTest
    @EnumSource(value = PgpPublicKeyAlgorithm.class, names = {"RSA", "ECDSA", "EDDSA", "ML_DSA_65_ED25519"})
    void supportsSigning_givenSignatureCapableAlgorithm_thenReturnsTrue(PgpPublicKeyAlgorithm algorithm) {
        assertThat(algorithm.supportsSigning()).isTrue();
    }

    @ParameterizedTest
    @EnumSource(value = PgpPublicKeyAlgorithm.class, names = {"X25519", "ECDH", "ML_KEM_768_X25519"})
    void supportsSigning_givenEncryptionOnlyAlgorithm_thenReturnsFalse(PgpPublicKeyAlgorithm algorithm) {
        assertThat(algorithm.supportsSigning()).isFalse();
    }

    @ParameterizedTest
    @EnumSource(value = PgpPublicKeyAlgorithm.class, names = {"X25519", "ECDH", "ML_KEM_768_X25519"})
    void requiresSenderKeyAgreementKey_givenKeyAgreementBasedAlgorithm_thenReturnsTrue(
            PgpPublicKeyAlgorithm algorithm) {
        assertThat(algorithm.requiresSenderKeyAgreementKey()).isTrue();
    }

    @ParameterizedTest
    @EnumSource(value = PgpPublicKeyAlgorithm.class, names = {"RSA", "ECDSA", "EDDSA", "ML_DSA_65_ED25519"})
    void requiresSenderKeyAgreementKey_givenNonKeyAgreementBasedAlgorithm_thenReturnsFalse(
            PgpPublicKeyAlgorithm algorithm) {
        assertThat(algorithm.requiresSenderKeyAgreementKey()).isFalse();
    }
}
