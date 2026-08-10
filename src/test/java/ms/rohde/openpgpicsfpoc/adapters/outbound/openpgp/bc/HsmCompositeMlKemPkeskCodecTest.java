package ms.rohde.openpgpicsfpoc.adapters.outbound.openpgp.bc;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.PacketTags;
import org.junit.jupiter.api.Test;

/**
 * Verifiziert das reine Byte-Layout von {@link HsmCompositeMlKemPkeskCodec} - zunaechst
 * strukturell (Kodieren gefolgt von Dekodieren liefert die Ausgangswerte zurueck), dann
 * byte-exakt gegen die realen, armored PKESK-Pakete aus RFC 9980 Appendix A.2.3 (v3-PKESK)
 * und A.2.4 (v6-PKESK) - jeweils entpackt mit Bouncy Castles eigenem
 * {@link ArmoredInputStream} (reine Base64-/CRC24-Entschachtelung, keine Algorithmus-35-
 * spezifische BC-Logik und daher unproblematisch, siehe {@link HsmBackedOpenPgpMessageCodec}
 * fuer die Abgrenzung).
 */
class HsmCompositeMlKemPkeskCodecTest {

    private static final HexFormat HEX = HexFormat.of();

    // ------------------------------------------------------------------
    // Strukturelle Rundlauf-Tests (synthetische Daten)
    // ------------------------------------------------------------------

    @Test
    void algorithmSpecificDataRoundTrip_givenV3Pkesk_thenDecodesToOriginalFields() {
        byte[] ecdhCipherText = fill((byte) 0x11, CompositeMlKemKeyMaterial.ECDH_PUBLIC_KEY_LENGTH);
        byte[] mlkemCipherText = fill((byte) 0x22, CompositeMlKemKeyMaterial.MLKEM_CIPHERTEXT_LENGTH);
        byte[] wrappedSessionKey = fill((byte) 0x33, 40);
        int symAlgId = 9;

        byte[] encoded = HsmCompositeMlKemPkeskCodec.encodeAlgorithmSpecificData(
                ecdhCipherText, mlkemCipherText, wrappedSessionKey, true, symAlgId);
        var decoded = HsmCompositeMlKemPkeskCodec.decodeAlgorithmSpecificData(encoded, true);

        assertThat(decoded.ecdhCipherText()).isEqualTo(ecdhCipherText);
        assertThat(decoded.mlkemCipherText()).isEqualTo(mlkemCipherText);
        assertThat(decoded.symAlgId()).isEqualTo(symAlgId);
        assertThat(decoded.wrappedSessionKey()).isEqualTo(wrappedSessionKey);
    }

    @Test
    void algorithmSpecificDataRoundTrip_givenV6Pkesk_thenDecodesWithoutSymAlgIdField() {
        byte[] ecdhCipherText = fill((byte) 0x44, CompositeMlKemKeyMaterial.ECDH_PUBLIC_KEY_LENGTH);
        byte[] mlkemCipherText = fill((byte) 0x55, CompositeMlKemKeyMaterial.MLKEM_CIPHERTEXT_LENGTH);
        byte[] wrappedSessionKey = fill((byte) 0x66, 40);

        byte[] encoded = HsmCompositeMlKemPkeskCodec.encodeAlgorithmSpecificData(
                ecdhCipherText, mlkemCipherText, wrappedSessionKey, false, 0);
        var decoded = HsmCompositeMlKemPkeskCodec.decodeAlgorithmSpecificData(encoded, false);

        assertThat(decoded.ecdhCipherText()).isEqualTo(ecdhCipherText);
        assertThat(decoded.mlkemCipherText()).isEqualTo(mlkemCipherText);
        assertThat(decoded.wrappedSessionKey()).isEqualTo(wrappedSessionKey);
        // v6 traegt kein eigenes symAlgId-Feld - der um ein Byte kuerzere kodierte Puffer ist
        // der direkte Nachweis, dass encodeAlgorithmSpecificData es tatsaechlich weglaesst.
        assertThat(encoded.length)
                .isEqualTo(ecdhCipherText.length + mlkemCipherText.length + 1 + wrappedSessionKey.length);
    }

    @Test
    void readPacketHeader_givenNewFormatTwoOctetLength_thenParsesTagAndBody() {
        byte[] body = fill((byte) 0x77, 300);
        var out = new ByteArrayOutputStream();
        out.write(0xC0 | 1); // neues Format, Tag 1 (PKESK)
        int lengthField = body.length - 192;
        out.write(192 + (lengthField >> 8));
        out.write(lengthField & 0xFF);
        out.writeBytes(body);

        var packet = HsmCompositeMlKemPkeskCodec.readPacketHeader(out.toByteArray(), 0);

        assertThat(packet.tag()).isEqualTo(PacketTags.PUBLIC_KEY_ENC_SESSION);
        assertThat(packet.body()).isEqualTo(body);
        assertThat(packet.totalLength()).isEqualTo(out.size());
    }

    // ------------------------------------------------------------------
    // Byte-exakte Verifikation gegen RFC 9980 Appendix A.2.3 (v3-PKESK / SEIPD v1)
    // ------------------------------------------------------------------

    @Test
    void parsePkesk_givenAppendixA23V3Message_thenMatchesRfcFields() throws IOException {
        byte[] message = unarmor(APPENDIX_A23_MESSAGE_V1);

        var leadingPacket = HsmCompositeMlKemPkeskCodec.readPacketHeader(message, 0);
        assertThat(leadingPacket.tag()).isEqualTo(PacketTags.PUBLIC_KEY_ENC_SESSION);

        var header = HsmCompositeMlKemPkeskCodec.parsePkeskBody(leadingPacket.body());
        assertThat(header.version()).isEqualTo(3);
        assertThat(header.keyId()).isEqualTo(Long.parseUnsignedLong("a4f95f985ed61a51", 16));
        assertThat(header.algorithm()).isEqualTo(35);

        var algorithmSpecific = HsmCompositeMlKemPkeskCodec.decodeAlgorithmSpecificData(header.algorithmSpecificData(), true);
        assertThat(algorithmSpecific.ecdhCipherText())
                .isEqualTo(HEX.parseHex("ca0ac6b550882901dbb78f2951de038a5360c29903abb597cb32acfdbeb0450b"));
        assertThat(algorithmSpecific.mlkemCipherText()).hasSize(CompositeMlKemKeyMaterial.MLKEM_CIPHERTEXT_LENGTH);
        assertThat(algorithmSpecific.symAlgId()).isEqualTo(9); // AES-256, RFC 9980 Section 4.3.1 (v3 MUSS AES sein)
        assertThat(algorithmSpecific.wrappedSessionKey())
                .isEqualTo(HEX.parseHex("d1bfe58397e83a28dd59554d18b4d10982b7cef5e9e1092ddee2be8ac560510b63978e11472398d2"));

        // Die berechnete Paketlaenge muss exakt auf den Beginn des naechsten (SEIPD-)Pakets zeigen.
        var nextPacket = HsmCompositeMlKemPkeskCodec.readPacketHeader(message, leadingPacket.totalLength());
        assertThat(nextPacket.tag()).isEqualTo(PacketTags.SYM_ENC_INTEGRITY_PRO);
    }

    // ------------------------------------------------------------------
    // Byte-exakte Verifikation gegen RFC 9980 Appendix A.2.4 (v6-PKESK / SEIPD v2)
    // ------------------------------------------------------------------

    @Test
    void parsePkesk_givenAppendixA24V6Message_thenMatchesRfcFields() throws IOException {
        byte[] message = unarmor(APPENDIX_A24_MESSAGE_V2);

        var leadingPacket = HsmCompositeMlKemPkeskCodec.readPacketHeader(message, 0);
        assertThat(leadingPacket.tag()).isEqualTo(PacketTags.PUBLIC_KEY_ENC_SESSION);

        var header = HsmCompositeMlKemPkeskCodec.parsePkeskBody(leadingPacket.body());
        assertThat(header.version()).isEqualTo(6);
        assertThat(header.keyVersion()).isEqualTo(4);
        assertThat(header.fingerprint()).isEqualTo(HEX.parseHex("e51dbfea51936988b5428fffa4f95f985ed61a51"));
        assertThat(header.algorithm()).isEqualTo(35);

        var algorithmSpecific = HsmCompositeMlKemPkeskCodec.decodeAlgorithmSpecificData(header.algorithmSpecificData(), false);
        assertThat(algorithmSpecific.ecdhCipherText())
                .isEqualTo(HEX.parseHex("95e8c3ced627776c62814dce91cf3a32c188fb04de44ed4b355cb82f4dca1b4e"));
        assertThat(algorithmSpecific.mlkemCipherText()).hasSize(CompositeMlKemKeyMaterial.MLKEM_CIPHERTEXT_LENGTH);
        assertThat(algorithmSpecific.wrappedSessionKey())
                .isEqualTo(HEX.parseHex("5ff671107a794dc0981518f352f3b898208d634bb7cff0ae98c9f927c8328dcc38cf08910a2fb838"));

        var nextPacket = HsmCompositeMlKemPkeskCodec.readPacketHeader(message, leadingPacket.totalLength());
        assertThat(nextPacket.tag()).isEqualTo(PacketTags.SYM_ENC_INTEGRITY_PRO);
    }

    private static byte[] fill(byte value, int length) {
        byte[] result = new byte[length];
        java.util.Arrays.fill(result, value);
        return result;
    }

    private static byte[] unarmor(String armored) throws IOException {
        try (var in = new ArmoredInputStream(new ByteArrayInputStream(armored.getBytes(StandardCharsets.US_ASCII)));
                var out = new ByteArrayOutputStream()) {
            in.transferTo(out);
            return out.toByteArray();
        }
    }

    // Woertlich aus RFC 9980 Appendix A.2.3 uebernommen ("Testing\n", verschluesselt an den
    // Empfaenger aus Appendix A.2.2, v3-PKESK + SEIPD v1).
    private static final String APPENDIX_A23_MESSAGE_V1 =
            """
            -----BEGIN PGP MESSAGE-----

            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
            Wfo=
            -----END PGP MESSAGE-----
            """;

    // Woertlich aus RFC 9980 Appendix A.2.4 uebernommen (dieselbe Nachricht wie A.2.3, jedoch
    // v6-PKESK + SEIPD v2/AEAD).
    private static final String APPENDIX_A24_MESSAGE_V2 =
            """
            -----BEGIN PGP MESSAGE-----

            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
            -----END PGP MESSAGE-----
            """;
}
