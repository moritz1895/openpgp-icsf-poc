package ms.rohde.openpgpicsfpoc.adapters.outbound.openpgp.bc;

import java.io.IOException;
import java.io.OutputStream;

/**
 * Puffert beliebig grosse {@code write()}-Aufrufe zu 16-Byte-Fenstern und
 * verschluesselt jedes Fenster (das letzte ggf. unvollstaendig) ueber
 * {@link HsmCfbEngine}.
 */
final class HsmCfbOutputStream extends OutputStream {

    private final OutputStream delegate;
    private final HsmCfbEngine engine;
    private final byte[] pending = new byte[HsmCfbEngine.blockLength()];
    private int pendingLength;
    private boolean closed;

    HsmCfbOutputStream(OutputStream delegate, HsmCfbEngine engine) {
        this.delegate = delegate;
        this.engine = engine;
    }

    @Override
    public void write(int b) throws IOException {
        pending[pendingLength++] = (byte) b;
        if (pendingLength == pending.length) {
            flushFullBlock();
        }
    }

    @Override
    public void write(byte[] b, int off, int len) throws IOException {
        int remaining = len;
        int offset = off;
        while (remaining > 0) {
            int toCopy = Math.min(remaining, pending.length - pendingLength);
            System.arraycopy(b, offset, pending, pendingLength, toCopy);
            pendingLength += toCopy;
            offset += toCopy;
            remaining -= toCopy;
            if (pendingLength == pending.length) {
                flushFullBlock();
            }
        }
    }

    private void flushFullBlock() throws IOException {
        delegate.write(engine.encryptBlock(pending, pending.length));
        pendingLength = 0;
    }

    @Override
    public void close() throws IOException {
        if (closed) {
            return;
        }
        closed = true;
        if (pendingLength > 0) {
            delegate.write(engine.encryptBlock(pending, pendingLength));
        }
        delegate.close();
    }
}
