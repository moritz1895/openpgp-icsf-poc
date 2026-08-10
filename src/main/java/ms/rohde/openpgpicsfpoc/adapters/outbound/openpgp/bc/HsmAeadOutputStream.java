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
