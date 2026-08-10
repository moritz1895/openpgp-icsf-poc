package ms.rohde.openpgpicsfpoc.adapters.outbound.openpgp.bc;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;
import org.bouncycastle.bcpg.PublicKeyEncSessionPacket;

/**
 * Reine (kryptographiefreie) Byte-Layout-Kodierung/-Dekodierung fuer das PKESK-Paket
 * des kompositen ML-KEM-768+X25519-Verfahrens (RFC 9980 Section 4.3.1) sowie fuer das
 * generische OpenPGP-Paket-Framing (Tag + Laenge), das zum Lokalisieren dieses Pakets
 * innerhalb einer rohen Nachricht benoetigt wird.
 *
 * <p><b>Warum eigenes Framing?</b> {@code bcpg-jdk18on} 1.85 kennt Algorithmus-ID 35
 * nicht (siehe {@link PgpKeyMaterialCodec#COMPOSITE_ML_KEM_768_X25519_ALGORITHM_TAG}) -
 * sein eigener paket-lesender Konstruktor fuer
 * {@link org.bouncycastle.bcpg.PublicKeyEncSessionPacket} wirft beim Antreffen dieser
 * Algorithmus-ID eine {@code IOException} ("unknown PGP public key algorithm
 * encountered"), noch bevor eigener Code eingreifen koennte - {@code PGPObjectFactory}
 * kann ein PKESK-Paket dieses Algorithmus daher grundsaetzlich nicht einlesen. Diese
 * Klasse uebernimmt deshalb das Lesen der Paket-Rahmung sowie des PKESK-Kopfes
 * (Version, Schluessel-ID/Fingerabdruck, Algorithmus) manuell - rein strukturelle
 * Kodierungslogik ohne jede kryptographische Operation, siehe
 * {@link HsmCompositeMlKemKeyEncryptionMethodGenerator}/
 * {@link HsmCompositeMlKemPublicKeyDataDecryptorFactory} fuer die Orchestrierung der
 * eigentlichen Kryptographie.
 */
final class HsmCompositeMlKemPkeskCodec {

    private HsmCompositeMlKemPkeskCodec() {}

    // ------------------------------------------------------------------
    // Algorithmus-spezifischer PKESK-Nutzdatenteil (RFC 9980 Section 4.3.1)
    // ------------------------------------------------------------------

    /**
     * Kodiert {@code ecdhCipherText || mlkemCipherText || len(C, symAlgId) || [symAlgId]
     * || C} - der algorithmus-spezifische Teil eines PKESK-Pakets fuer Algorithmus-ID 35.
     * {@code symAlgId} wird nur fuer ein v3-PKESK mit ausgegeben (siehe RFC 9980 Section
     * 4.3.1: "the symmetric algorithm identifier is not encrypted [...] it is prepended
     * to the wrapped session key in plaintext").
     */
    static byte[] encodeAlgorithmSpecificData(
            byte[] ecdhCipherText, byte[] mlkemCipherText, byte[] wrappedSessionKey, boolean isV3, int symAlgId) {
        int fieldsLength = wrappedSessionKey.length + (isV3 ? 1 : 0);
        if (fieldsLength > 0xFF) {
            throw new IllegalArgumentException("Kombinierte Feldlaenge " + fieldsLength + " uebersteigt ein Oktett");
        }
        var out = new ByteArrayOutputStream();
        out.writeBytes(ecdhCipherText);
        out.writeBytes(mlkemCipherText);
        out.write(fieldsLength);
        if (isV3) {
            out.write(symAlgId);
        }
        out.writeBytes(wrappedSessionKey);
        return out.toByteArray();
    }

    /**
     * Zerlegt den algorithmus-spezifischen PKESK-Nutzdatenteil - Gegenstueck zu
     * {@link #encodeAlgorithmSpecificData(byte[], byte[], byte[], boolean, int)}.
     * {@code symAlgId} ist nur fuer {@code isV3 == true} sinnvoll gesetzt (RFC 9980
     * Section 4.3.1: bei einem v6-PKESK gibt es kein eigenes symAlgId-Feld - der
     * symmetrische Algorithmus ergibt sich dort aus dem SEIPD-v2-Paket selbst).
     */
    static DecodedAlgorithmSpecificData decodeAlgorithmSpecificData(byte[] payload, boolean isV3) {
        int offset = 0;
        byte[] ecdhCipherText = Arrays.copyOfRange(payload, offset, offset + CompositeMlKemKeyMaterial.ECDH_PUBLIC_KEY_LENGTH);
        offset += CompositeMlKemKeyMaterial.ECDH_PUBLIC_KEY_LENGTH;
        byte[] mlkemCipherText =
                Arrays.copyOfRange(payload, offset, offset + CompositeMlKemKeyMaterial.MLKEM_CIPHERTEXT_LENGTH);
        offset += CompositeMlKemKeyMaterial.MLKEM_CIPHERTEXT_LENGTH;
        int fieldsLength = payload[offset++] & 0xFF;
        int symAlgId = -1;
        if (isV3) {
            symAlgId = payload[offset++] & 0xFF;
        }
        int wrappedLength = fieldsLength - (isV3 ? 1 : 0);
        byte[] wrappedSessionKey = Arrays.copyOfRange(payload, offset, offset + wrappedLength);
        return new DecodedAlgorithmSpecificData(ecdhCipherText, mlkemCipherText, symAlgId, wrappedSessionKey);
    }

    record DecodedAlgorithmSpecificData(byte[] ecdhCipherText, byte[] mlkemCipherText, int symAlgId, byte[] wrappedSessionKey) {}

    // ------------------------------------------------------------------
    // Generisches OpenPGP-Paket-Framing (Tag + Laenge) - Neu-Format, wie es
    // PGPEncryptedDataGenerator fuer das PKESK-Paket erzeugt (definite length,
    // keine Partial-Body-Kette).
    // ------------------------------------------------------------------

    record RawPacket(int tag, byte[] body, int totalLength) {}

    static RawPacket readPacketHeader(byte[] data, int offset) {
        int first = data[offset] & 0xFF;
        if ((first & 0x80) == 0) {
            throw new OpenPgpMessageCodecException("Kein gueltiger OpenPGP-Paket-Header an Position " + offset, null);
        }
        if ((first & 0x40) == 0) {
            return readOldFormatPacketHeader(data, offset, first);
        }
        int tag = first & 0x3F;
        int l1 = data[offset + 1] & 0xFF;
        int headerLength;
        int bodyLength;
        if (l1 < 192) {
            bodyLength = l1;
            headerLength = 2;
        } else if (l1 < 224) {
            bodyLength = ((l1 - 192) << 8) + (data[offset + 2] & 0xFF) + 192;
            headerLength = 3;
        } else if (l1 == 255) {
            bodyLength = ((data[offset + 2] & 0xFF) << 24)
                    | ((data[offset + 3] & 0xFF) << 16)
                    | ((data[offset + 4] & 0xFF) << 8)
                    | (data[offset + 5] & 0xFF);
            headerLength = 6;
        } else {
            throw new OpenPgpMessageCodecException(
                    "Partial-Body-Length wird fuer das PKESK-Paket dieser Bridge nicht erwartet", null);
        }
        byte[] body = Arrays.copyOfRange(data, offset + headerLength, offset + headerLength + bodyLength);
        return new RawPacket(tag, body, headerLength + bodyLength);
    }

    private static RawPacket readOldFormatPacketHeader(byte[] data, int offset, int first) {
        int tag = (first >> 2) & 0x0F;
        int lengthType = first & 0x03;
        int headerLength;
        int bodyLength;
        switch (lengthType) {
            case 0 -> {
                bodyLength = data[offset + 1] & 0xFF;
                headerLength = 2;
            }
            case 1 -> {
                bodyLength = ((data[offset + 1] & 0xFF) << 8) | (data[offset + 2] & 0xFF);
                headerLength = 3;
            }
            case 2 -> {
                bodyLength = ((data[offset + 1] & 0xFF) << 24)
                        | ((data[offset + 2] & 0xFF) << 16)
                        | ((data[offset + 3] & 0xFF) << 8)
                        | (data[offset + 4] & 0xFF);
                headerLength = 5;
            }
            default ->
                throw new OpenPgpMessageCodecException(
                        "Unbestimmte Paketlaenge (old format) wird nicht unterstuetzt", null);
        }
        byte[] body = Arrays.copyOfRange(data, offset + headerLength, offset + headerLength + bodyLength);
        return new RawPacket(tag, body, headerLength + bodyLength);
    }

    // ------------------------------------------------------------------
    // PKESK-Paketkopf (Version, Schluessel-ID/Fingerabdruck, Algorithmus)
    // ------------------------------------------------------------------

    record ParsedPkeskHeader(
            int version, long keyId, int keyVersion, byte[] fingerprint, int algorithm, byte[] algorithmSpecificData) {}

    static ParsedPkeskHeader parsePkeskBody(byte[] body) {
        int offset = 0;
        int version = body[offset++] & 0xFF;
        long keyId = 0;
        int keyVersion = 0;
        byte[] fingerprint = new byte[0];
        if (version == PublicKeyEncSessionPacket.VERSION_3) {
            keyId = readKeyId(body, offset);
            offset += 8;
        } else if (version == PublicKeyEncSessionPacket.VERSION_6) {
            int keyInfoLength = body[offset++] & 0xFF;
            if (keyInfoLength != 0) {
                keyVersion = body[offset++] & 0xFF;
                fingerprint = Arrays.copyOfRange(body, offset, offset + keyInfoLength - 1);
                offset += keyInfoLength - 1;
            }
        } else {
            throw new OpenPgpMessageCodecException("Nicht unterstuetzte PKESK-Paketversion " + version, null);
        }
        int algorithm = body[offset++] & 0xFF;
        byte[] algorithmSpecificData = Arrays.copyOfRange(body, offset, body.length);
        return new ParsedPkeskHeader(version, keyId, keyVersion, fingerprint, algorithm, algorithmSpecificData);
    }

    private static long readKeyId(byte[] data, int offset) {
        long value = 0;
        for (int i = 0; i < 8; i++) {
            value = (value << 8) | (data[offset + i] & 0xFFL);
        }
        return value;
    }
}
