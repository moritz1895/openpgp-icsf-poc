package ms.rohde.openpgpicsfpoc.adapters.outbound.hsm.dummy;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import ms.rohde.openpgpicsfpoc.core.domain.HsmKeyHandle;
import org.jspecify.annotations.Nullable;

/**
 * <b>Kein Produktivcode - reines Testdouble.</b>
 *
 * <p>Einfacher In-Memory-Schluesselspeicher, der {@link HsmKeyHandle} auf
 * echtes (nur fuer die Simulation lokal gehaltenes) Schluesselmaterial
 * abbildet. Ein echter ICSF-Adapter wuerde stattdessen mit HSM-residenten
 * Key-Token/Labels arbeiten, bei denen privates Schluesselmaterial die
 * HSM-Grenze nie verlaesst. Dieser Speicher dient ausschliesslich der
 * funktionalen Nachbildung der Hsm-Primitiven in dieser PoC.</p>
 *
 * <p>Sowohl eigene Schluesselpaare (mit privatem Teil, fuer Entschluesselung/
 * Signatur/Decapsulate) als auch importierte Gegenstellen-Schluessel (nur
 * oeffentlicher Teil, fuer Verschluesselung/Schluesselaustausch/Encapsulate)
 * werden ueber denselben Handle-Mechanismus verwaltet.</p>
 */
public final class InMemoryHsmKeyStore {

    private record StoredKey(PublicKey publicKey, @Nullable PrivateKey privateKey) {}

    private final Map<HsmKeyHandle, StoredKey> keysByHandle = new ConcurrentHashMap<>();

    public InMemoryHsmKeyStore() {}

    public void registerKeyPair(HsmKeyHandle handle, KeyPair keyPair) {
        Objects.requireNonNull(handle, "handle darf nicht null sein");
        Objects.requireNonNull(keyPair, "keyPair darf nicht null sein");
        keysByHandle.put(handle, new StoredKey(keyPair.getPublic(), keyPair.getPrivate()));
    }

    public void registerPublicKey(HsmKeyHandle handle, PublicKey publicKey) {
        Objects.requireNonNull(handle, "handle darf nicht null sein");
        Objects.requireNonNull(publicKey, "publicKey darf nicht null sein");
        keysByHandle.put(handle, new StoredKey(publicKey, null));
    }

    public PublicKey requirePublicKey(HsmKeyHandle handle) {
        return requireStoredKey(handle).publicKey();
    }

    public PrivateKey requirePrivateKey(HsmKeyHandle handle) {
        PrivateKey privateKey = requireStoredKey(handle).privateKey();
        if (privateKey == null) {
            throw new IllegalStateException(
                    "Fuer Handle " + handle + " ist kein privates Schluesselmaterial registriert");
        }
        return privateKey;
    }

    private StoredKey requireStoredKey(HsmKeyHandle handle) {
        Objects.requireNonNull(handle, "handle darf nicht null sein");
        StoredKey storedKey = keysByHandle.get(handle);
        if (storedKey == null) {
            throw new IllegalStateException("Unbekannter Hsm-Key-Handle: " + handle);
        }
        return storedKey;
    }
}
