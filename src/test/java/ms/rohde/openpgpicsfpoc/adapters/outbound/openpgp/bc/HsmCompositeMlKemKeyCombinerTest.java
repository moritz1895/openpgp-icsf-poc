package ms.rohde.openpgpicsfpoc.adapters.outbound.openpgp.bc;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.HexFormat;
import ms.rohde.openpgpicsfpoc.adapters.outbound.hsm.dummy.DummyHsmAesEncryptionExecutor;
import org.junit.jupiter.api.Test;

/**
 * Verifiziert {@link HsmCompositeMlKemKeyCombiner#multiKeyCombine(byte[], byte[], byte[],
 * byte[], byte)} byte-exakt gegen die Testvektoren aus RFC 9980 Appendix A.2 (v4-Schluessel,
 * die fuer diese PoC relevante Zielgroesse - siehe Aufgabenstellung).
 *
 * <p><b>Herkunft der Werte:</b> {@code mlkemKeyShare}, {@code ecdhKeyShare}, der erwartete
 * {@code KEK}-Output und der erwartete Sitzungsschluessel sind direkt aus dem RFC-Text
 * (Appendix A.2.3 fuer das v3-PKESK/SEIPD-v1-Beispiel, Appendix A.2.4 fuer das
 * v6-PKESK/SEIPD-v2-Beispiel) uebernommen. {@code ecdhCipherText}, das gewickelte
 * {@code C} und das rekonstruierte {@code ecdhPublicKey} des Empfaengers sind <b>nicht</b>
 * im RFC-Text als eigener Hex-String angegeben, sondern wurden lokal aus den im RFC ebenfalls
 * enthaltenen armored Schluessel-/Nachrichten-Bloecken (Appendix A.2.2 Public Key, A.2.3/A.2.4
 * Message) durch manuelles Zerlegen des OpenPGP-Paket-Framings extrahiert (Byte-Bereiche des
 * ML-KEM-768+X25519-oeffentlichen-Subkey- bzw. PKESK-Pakets) - reine Paket-Framing-Arbeit
 * (Tag/Laenge lesen, Byte-Bereiche kopieren), keine Kryptographie.
 *
 * <p>Diese Extraktion ist stark gegenkontrolliert: mit den hier hart kodierten Werten
 * reproduzieren beide Testfaelle unten sowohl den im RFC angegebenen KEK-Wert <b>als auch</b>
 * (durch zusaetzliches {@code AESKeyUnwrap(KEK, C)} ueber {@link HsmAesKeyWrap}, das bereits
 * eigenstaendig gegen NIST-Testvektoren verifiziert ist, siehe {@code HsmAesKeyWrapTest}) den
 * im RFC angegebenen Sitzungsschluessel-Wert - ein Zufallstreffer bei einer falschen Extraktion
 * waere praktisch ausgeschlossen. Damit sind sowohl die {@code multiKeyCombine}-Formel selbst
 * (Reihenfolge/Inhalt der verketteten Eingaben, Domain-Separator, SHA3-256) als auch das
 * PKESK-Byte-Layout (Position von {@code ecdhCipherText}/{@code C} innerhalb des Pakets, siehe
 * auch {@link HsmCompositeMlKemPkeskCodecTest}) gegen RFC-Bytes verifiziert.
 *
 * <p><b>Nicht</b> verifiziert ist das Parsen des RFC-eigenen Secret-Key-Blocks durch diese PoC
 * selbst (das PoC-Schluesselmodell kennt nur {@code HsmKeyHandle}-referenzierte Schluessel,
 * kein Parsen echter Secret-Key-Pakete) - siehe {@link HsmBackedOpenPgpMessageCodecIntegrationTest}
 * fuer den vollstaendigen Rundlauf-Nachweis mit PoC-eigenen (nicht RFC-)Schluesseln.
 */
class HsmCompositeMlKemKeyCombinerTest {

    private static final HexFormat HEX = HexFormat.of();

    // Aus dem oeffentlichen Schluessel Appendix A.2.2 extrahiert (ML-KEM-768+X25519-Subkey-Paket,
    // erste 32 Byte des algorithmus-spezifischen Teils) - fuer beide Testvektoren identisch, da
    // derselbe Empfaengerschluessel.
    private static final byte[] RECIPIENT_ECDH_PUBLIC_KEY =
            HEX.parseHex("b087eaa031ebdd5503efab23f493fed388f31de0214d79e83c5dcdec2b36f355");

    private static final byte ALGORITHM_ID = 35;

    @Test
    void multiKeyCombine_givenAppendixA23Vectors_thenMatchesRfcKekAndSessionKey() {
        byte[] mlkemKeyShare = HEX.parseHex("16f2aea8ec1ca277c04cc7b87681d7d38511a38f554775a8fc4de41aa76eb586");
        byte[] ecdhKeyShare = HEX.parseHex("2fc0c8fcace9636c86d1ee1715a302819ad48c549579a462a33eed36627c532e");
        byte[] expectedKek = HEX.parseHex("c1591d7511f9f0213bfd57cf316e5ec0d40c4ea826fa989ab606aa3b8a1a2c1f");
        byte[] expectedSessionKey = HEX.parseHex("b4dc7197e1519822ca689da484643edf272934d98ae1974b5d88317a7a6a3c4f");
        // Aus dem v3-PKESK-Paket der Appendix-A.2.3-Nachricht extrahiert.
        byte[] ecdhCipherText = HEX.parseHex("ca0ac6b550882901dbb78f2951de038a5360c29903abb597cb32acfdbeb0450b");
        byte[] wrappedSessionKey =
                HEX.parseHex("d1bfe58397e83a28dd59554d18b4d10982b7cef5e9e1092ddee2be8ac560510b63978e11472398d2");

        byte[] kek = HsmCompositeMlKemKeyCombiner.multiKeyCombine(
                mlkemKeyShare, ecdhKeyShare, ecdhCipherText, RECIPIENT_ECDH_PUBLIC_KEY, ALGORITHM_ID);

        assertThat(kek).isEqualTo(expectedKek);
        var wrap = new HsmAesKeyWrap(new DummyHsmAesEncryptionExecutor(), kek);
        assertThat(wrap.unwrap(wrappedSessionKey)).isEqualTo(expectedSessionKey);
    }

    @Test
    void multiKeyCombine_givenAppendixA24Vectors_thenMatchesRfcKekAndSessionKey() {
        byte[] mlkemKeyShare = HEX.parseHex("16a22adbeced91ada60b5561611748edd2fedc51e0770f86d7394870062e7322");
        byte[] ecdhKeyShare = HEX.parseHex("5ac67eab192f25ac99d87543e6fcd3a4769cb02c9d1afdc79354c2baa2289e29");
        byte[] expectedKek = HEX.parseHex("5c5652a690b55d1e9545fbd722f838cd8ff4d3657af5a9026d02f3185ca74993");
        byte[] expectedSessionKey = HEX.parseHex("160867d96032b640208c1c92174d0270bb89189d72320711acd221bbea2a26b6");
        // Aus dem v6-PKESK-Paket der Appendix-A.2.4-Nachricht extrahiert.
        byte[] ecdhCipherText = HEX.parseHex("95e8c3ced627776c62814dce91cf3a32c188fb04de44ed4b355cb82f4dca1b4e");
        byte[] wrappedSessionKey =
                HEX.parseHex("5ff671107a794dc0981518f352f3b898208d634bb7cff0ae98c9f927c8328dcc38cf08910a2fb838");

        byte[] kek = HsmCompositeMlKemKeyCombiner.multiKeyCombine(
                mlkemKeyShare, ecdhKeyShare, ecdhCipherText, RECIPIENT_ECDH_PUBLIC_KEY, ALGORITHM_ID);

        assertThat(kek).isEqualTo(expectedKek);
        var wrap = new HsmAesKeyWrap(new DummyHsmAesEncryptionExecutor(), kek);
        assertThat(wrap.unwrap(wrappedSessionKey)).isEqualTo(expectedSessionKey);
    }
}
