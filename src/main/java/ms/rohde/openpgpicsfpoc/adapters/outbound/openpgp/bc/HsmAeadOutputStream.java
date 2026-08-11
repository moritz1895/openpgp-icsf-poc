package ms.rohde.openpgpicsfpoc.adapters.outbound.openpgp.bc;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Arrays;

/**
 * Chunk-weise AES-256-GCM-Verschluesselung fuer das AEAD-Verschluesselungsprofil
 * (SEIPD v2), Chunk-Groesse gemaess RFC 9580 Section 5.13.2. Puffert
 * Klartext bis zur konfigurierten Chunk-Groesse und verschluesselt jeden
 * vollen Chunk sofort ueber {@link HsmAeadChunkCodec}; beim Schliessen wird
 * ein etwaiger letzter Teil-Chunk regulaer verschluesselt und zusaetzlich der
 * abschliessende, laengenauthentisierende Nachrichten-Tag angehaengt.
 *
 * <p><b>Warum ueberhaupt Chunks statt eines einzelnen GCM-Aufrufs ueber die
 * gesamte Nachricht?</b> Das ist keine reine Streaming-Optimierung, sondern
 * von RFC 9580 Section 5.13.2 fuer SEIPD v2 zwingend vorgeschrieben: jeder
 * Chunk erhaelt sein eigenes GCM-Auth-Tag, sodass ein Angreifer die Nachricht
 * nicht erst vollstaendig puffern muesste, um sie zu faelschen - ein einzelner
 * Tag ueber Multi-Gigabyte-Nachrichten waere zudem in der Praxis (v.a. auf
 * einem HSM mit begrenztem Arbeitsspeicher) kaum handhabbar. Der
 * abschliessende Nachrichten-Tag (ueber leeren Klartext, aber mit der
 * Gesamtlaenge in den Additional Authenticated Data) verhindert zusaetzlich,
 * dass ein Angreifer die Nachricht unbemerkt um ganze Chunks kuerzt
 * (Truncation-Angriff) - ohne ihn waere ein vorzeitiger Stream-Abbruch nicht
 * von einer absichtlich kurzen Nachricht zu unterscheiden. Diese Klasse
 * nutzt die Chunk-Struktur daher zugleich fuer echtes Streaming (Bouncy
 * Castles {@code PGPEncryptedDataGenerator} schreibt den Klartext ohnehin
 * inkrementell ueber {@link #write(byte[], int, int)}), aber das waere ohne
 * die protokollseitige Chunk-Pflicht kein hinreichender Grund fuer diese
 * Klasse gewesen.</p>
 */
final class HsmAeadOutputStream extends OutputStream {

    private final OutputStream delegate;
    private final HsmAeadChunkCodec codec;
    private final byte[] buffer;

    private int bufferLength;
    private long chunkIndex;
    private long totalBytes;
    private boolean closed;

    HsmAeadOutputStream(OutputStream delegate, HsmAeadChunkCodec codec, int chunkSizeOctet) {
        this.delegate = delegate;
        this.codec = codec;
        this.buffer = new byte[(int) HsmAeadChunkCodec.chunkLength(chunkSizeOctet)];
    }

    @Override
    public void write(int b) throws IOException {
        write(new byte[] {(byte) b}, 0, 1);
    }

    @Override
    public void write(byte[] b, int off, int len) throws IOException {
        int remaining = len;
        int offset = off;
        while (remaining > 0) {
            int toCopy = Math.min(remaining, buffer.length - bufferLength);
            System.arraycopy(b, offset, buffer, bufferLength, toCopy);
            bufferLength += toCopy;
            offset += toCopy;
            remaining -= toCopy;
            if (bufferLength == buffer.length) {
                flushChunk();
            }
        }
    }

    private void flushChunk() throws IOException {
        byte[] ciphertextAndTag = codec.encryptChunk(Arrays.copyOf(buffer, bufferLength), chunkIndex);
        delegate.write(ciphertextAndTag);
        totalBytes += bufferLength;
        chunkIndex++;
        bufferLength = 0;
    }

    @Override
    public void close() throws IOException {
        if (closed) {
            return;
        }
        closed = true;
        if (bufferLength > 0) {
            flushChunk();
        }
        byte[] finalTag = codec.encryptFinalTag(chunkIndex, totalBytes);
        delegate.write(finalTag);
        delegate.close();
    }
}
