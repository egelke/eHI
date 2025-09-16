package be.egelke.ehealth.client;

import be.fgov.ehealth.etee.crypto.decrypt.DataUnsealer;
import be.fgov.ehealth.etee.crypto.decrypt.DataUnsealerBuilder;
import be.fgov.ehealth.etee.crypto.decrypt.UnsealedData;
import be.fgov.ehealth.etee.crypto.encrypt.DataSealer;
import be.fgov.ehealth.etee.crypto.encrypt.DataSealerBuilder;
import be.fgov.ehealth.etee.crypto.policies.*;
import be.fgov.ehealth.etee.crypto.status.CryptoResult;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

public class Receiver {

    private static final String AUTH_ALIAS = "authentication";

    public static void main(String[] args) throws Exception {
        char[] password = args[1].toCharArray();
        KeyStore ownStore = openKeyStore(args[0], password);
        String encAlias = null;
        Enumeration<String> aliases = ownStore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            if (!AUTH_ALIAS.equals(alias)) {
                encAlias = alias;
            }
        }
        EncryptionCredential credential = EncryptionCredential.create(
                (PrivateKey) ownStore.getKey(encAlias, password),
                ((X509Certificate) ownStore.getCertificate(encAlias)).getSerialNumber().toString()
        );

        password = args[3].toCharArray();
        KeyStore caStore = openKeyStore(args[2], password);

        DataUnsealer unsealer = DataUnsealerBuilder
                .newBuilder()
                .addOCSPPolicy(OCSPPolicy.NONE)
                .addSigningPolicy(caStore, SigningPolicy.EHEALTH_CERT)
                .addPublicKeyPolicy(EncryptionPolicy.KNOWN_RECIPIENT, credential)
                .addSecretKeyPolicy(EncryptionPolicy.UNKNOWN_RECIPIENT)
                .build();

        CryptoResult<UnsealedData> result;
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (FileInputStream fis = new FileInputStream(args[4])) {
            result = unsealer.unseal(fis, baos);
        }



        System.exit(0);
    }

    private static KeyStore openKeyStore(String file, char[] password) throws Exception {
        KeyStore store = KeyStore.getInstance("pkcs12");
        try (InputStream fin = new FileInputStream(file)) {
            store.load(fin, password);
        }
        return store;
    }
}
