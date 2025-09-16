package be.egelke.ehealth.client;

import be.fgov.ehealth.etee.crypto.encrypt.DataSealer;
import be.fgov.ehealth.etee.crypto.encrypt.DataSealerBuilder;
import be.fgov.ehealth.etee.crypto.policies.EncryptionPolicy;
import be.fgov.ehealth.etee.crypto.policies.OCSPPolicy;
import be.fgov.ehealth.etee.crypto.policies.SigningCredential;
import be.fgov.ehealth.etee.crypto.policies.SigningPolicy;

import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public class Sender {

    private static final String AUTH_ALIAS = "authentication";

    public static void main(String[] args) throws Exception {
        char[] password = args[1].toCharArray();
        KeyStore ownStore = openKeyStore(args[0], password);


        SigningCredential credential = SigningCredential.create(
                (PrivateKey) ownStore.getKey(AUTH_ALIAS, password),
                (X509Certificate) ownStore.getCertificate(AUTH_ALIAS),
                (X509Certificate) ownStore.getCertificateChain(AUTH_ALIAS)[1]
        );

        DataSealer sealer = DataSealerBuilder
                .newBuilder()
                .addOCSPPolicy(OCSPPolicy.NONE)
                .addSigningPolicy(SigningPolicy.EHEALTH_CERT, credential)
                .addPublicKeyPolicy(EncryptionPolicy.KNOWN_RECIPIENT)
                .addSecretKeyPolicy(EncryptionPolicy.UNKNOWN_RECIPIENT)
                .build();

        try (FileInputStream fis = new FileInputStream(args[4])) {

        }
    }

    private static KeyStore openKeyStore(String file, char[] password) throws Exception {
        KeyStore store = KeyStore.getInstance("pkcs12");
        try (InputStream fin = new FileInputStream(file)) {
            store.load(fin, password);
        }
        return store;
    }
}
