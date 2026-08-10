package ms.rohde.openpgpicsfpoc.ports.outbound.hsm;

/**
 * Von der {@link HsmSignature}-Primitive unterstuetzte Signaturalgorithmen.
 * Ein bewusst algorithmusagnostischer Port statt vier einzelner - spiegelt
 * CCAs reale Digital-Signature-Generate/Verify-Verben, die den Algorithmus
 * per Rule-Array-Keyword auswaehlen statt je Algorithmus ein eigenes Verb
 * anzubieten (siehe Projektplan).
 */
public enum HsmSignatureAlgorithm {
    RSA_PKCS1V15,
    ECDSA,
    EDDSA,
    ML_DSA_65_ED25519
}
