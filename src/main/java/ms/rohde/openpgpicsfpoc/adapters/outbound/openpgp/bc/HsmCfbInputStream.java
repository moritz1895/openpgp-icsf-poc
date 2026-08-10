package ms.rohde.openpgpicsfpoc.adapters.outbound.openpgp.bc;

import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;

/**
 * Gegenstueck zu {@link HsmCfbOutputStream} fuer die Entschluesselungsrichtung.
 */
final class HsmCfbInputStream extends InputStream {

    private final InputStream delegate;
    private final HsmCfbEngine engine;
    private final byte[] rawBlock = new byte[HsmCfbEngine.blockLength()];
    private byte[] outputBlock;
    private int outputPosition;
    private int outputLength;
    private boolean endOfStream;

    HsmCfbInputStream(InputStream delegate, HsmCfbEngine engine) {
        this.delegate = delegate;
        this.engine = engine;
    }

    @Override
    public int read() throws IOException {
        if (!ensureAvailable()) {
            return -1;
        }
        return outputBlock[outputPosition++] & 0xff;
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        if (len == 0) {
            return 0;
        }
        if (!ensureAvailable()) {
            return -1;
        }
        int available = outputLength - outputPosition;
        int toCopy = Math.min(len, available);
        System.arraycopy(outputBlock, outputPosition, b, off, toCopy);
        outputPosition += toCopy;
        return toCopy;
    }

    private boolean ensureAvailable() throws IOException {
        if (outputBlock != null && outputPosition < outputLength) {
            return true;
        }
        if (endOfStream) {
            return false;
        }

        int read = delegate.readNBytes(rawBlock, 0, rawBlock.length);
        if (read == 0) {
            endOfStream = true;
            return false;
        }
        if (read < rawBlock.length) {
            endOfStream = true;
        }

        outputBlock = engine.decryptBlock(Arrays.copyOf(rawBlock, read), read);
        outputLength = read;
        outputPosition = 0;
        return outputLength > 0;
    }
}
