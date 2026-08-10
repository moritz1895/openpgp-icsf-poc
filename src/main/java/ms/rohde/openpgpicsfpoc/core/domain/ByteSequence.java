package ms.rohde.openpgpicsfpoc.core.domain;

import java.util.Arrays;
import java.util.Objects;
import ms.rohde.hexagonalarch.annotations.DomainValueObject;

/**
 * Unveraenderlicher Byte-Container fuer kryptographisches Nutzmaterial
 * (Klartext, Chiffretext, Digest, Signatur, Shared Secret, ...).
 *
 * <p>Dient als einziger, wiederverwendbarer Werttyp fuer rohe Byte-Nutzdaten
 * innerhalb der Hsm-Primitiven und der OpenPGP-Domaene, damit Wertgleichheit
 * (statt Referenzgleichheit wie bei einem nackten {@code byte[]}) ueberall
 * konsistent funktioniert. Der interne Puffer wird beim Erzeugen und beim
 * Auslesen jeweils defensiv kopiert; {@link #toString()} gibt aus
 * Sicherheitsgruenden niemals den Inhalt aus.</p>
 */
@DomainValueObject
public final class ByteSequence {

    private final byte[] value;

    private ByteSequence(byte[] value) {
        this.value = value;
    }

    /**
     * Erzeugt eine {@code ByteSequence} als defensive Kopie der uebergebenen Bytes.
     */
    public static ByteSequence of(byte[] value) {
        Objects.requireNonNull(value, "value darf nicht null sein");
        return new ByteSequence(value.clone());
    }

    public static ByteSequence empty() {
        return new ByteSequence(new byte[0]);
    }

    /**
     * Liefert eine defensive Kopie der enthaltenen Bytes.
     */
    public byte[] value() {
        return value.clone();
    }

    public int length() {
        return value.length;
    }

    public boolean isEmpty() {
        return value.length == 0;
    }

    public ByteSequence concat(ByteSequence other) {
        Objects.requireNonNull(other, "other darf nicht null sein");
        byte[] combined = new byte[this.value.length + other.value.length];
        System.arraycopy(this.value, 0, combined, 0, this.value.length);
        System.arraycopy(other.value, 0, combined, this.value.length, other.value.length);
        return new ByteSequence(combined);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof ByteSequence other)) {
            return false;
        }
        return Arrays.equals(this.value, other.value);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(value);
    }

    @Override
    public String toString() {
        return "ByteSequence[length=" + value.length + "]";
    }
}
