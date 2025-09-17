package be.egelke.ehealth.client;

import be.fgov.ehealth.etee.crypto.decrypt.DataUnsealer;
import be.fgov.ehealth.etee.crypto.decrypt.DataUnsealerBuilder;
import be.fgov.ehealth.etee.crypto.decrypt.UnsealedData;
import be.fgov.ehealth.etee.crypto.encrypt.DataSealer;
import be.fgov.ehealth.etee.crypto.encrypt.DataSealerBuilder;
import be.fgov.ehealth.etee.crypto.encrypt.EncryptionToken;
import be.fgov.ehealth.etee.crypto.encrypt.EncryptionTokenFactory;
import be.fgov.ehealth.etee.crypto.policies.*;
import be.fgov.ehealth.etee.crypto.status.CryptoResult;
import lombok.extern.slf4j.Slf4j;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

@Slf4j
public class App {

    private static final String AUTH_ALIAS = "authentication";

    public static void main(String[] args) {
        try {
            if ("send".equalsIgnoreCase(args[0])) {
                send(args[1], args[2], args[3], args[4], args[5]);
                System.exit(0);
            } else if ("receive".equalsIgnoreCase(args[0])) {
                int retVal = receive(args[1], args[2], args[3], args[4]);
                System.exit(retVal);
            } else {
                log.warn("invalid action {}", args[0]);
                System.exit(-2);
            }
        } catch (Exception e) {
            log.error("error", e);
            System.exit(-1);
        }
    }

    public static void send(String storeFile, String storePwd, String clearFile, String cipherFile, String etkFile) throws Exception {
        char[] password = storePwd.toCharArray();
        KeyStore ownStore = openKeyStore(storeFile, password);


        SigningCredential sender = SigningCredential.create(
                (PrivateKey) ownStore.getKey(AUTH_ALIAS, password),
                (X509Certificate) ownStore.getCertificate(AUTH_ALIAS),
                (X509Certificate) ownStore.getCertificateChain(AUTH_ALIAS)[1]
        );

        DataSealer sealer = DataSealerBuilder
                .newBuilder()
                .addOCSPPolicy(OCSPPolicy.NONE)
                .addSigningPolicy(SigningPolicy.EHEALTH_CERT, sender)
                .addPublicKeyPolicy(EncryptionPolicy.KNOWN_RECIPIENT)
                .addSecretKeyPolicy(EncryptionPolicy.UNKNOWN_RECIPIENT)
                .build();

        try (
                FileInputStream clearStream = new FileInputStream(clearFile);
                FileOutputStream cipherStream = new FileOutputStream(cipherFile);
                FileInputStream etkSteam = new FileInputStream(etkFile);
        ) {
            EncryptionToken etk = EncryptionTokenFactory.getInstance().create(etkSteam);
            EncryptionCredential target = EncryptionCredential.create(etk.getCertificate());
            sealer.seal(clearStream, cipherStream, target);
        }
    }

    public static int receive(String storeFile, String storePwd, String cipherFile, String clearFile) throws Exception {
        char[] password = storePwd.toCharArray();
        KeyStore ownStore = openKeyStore(storeFile, password);
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

        password = "changeit".toCharArray();
        KeyStore caStore = openKeyStore(findCacertsPath(), password);

        DataUnsealer unsealer = DataUnsealerBuilder
                .newBuilder()
                .addOCSPPolicy(OCSPPolicy.NONE)
                .addSigningPolicy(caStore, SigningPolicy.EHEALTH_CERT)
                .addPublicKeyPolicy(EncryptionPolicy.KNOWN_RECIPIENT, credential)
                .addSecretKeyPolicy(EncryptionPolicy.UNKNOWN_RECIPIENT)
                .build();

        try (
                FileInputStream cipherStream = new FileInputStream(cipherFile);
                FileOutputStream clearStream = new FileOutputStream(clearFile);
        ) {
            CryptoResult<UnsealedData> result = unsealer.unseal(cipherStream, clearStream);
            if (result.hasErrors()) return -3;
        }
        return 0;
    }

    private static KeyStore openKeyStore(String file, char[] password) throws Exception {
        KeyStore store = KeyStore.getInstance("pkcs12");
        try (InputStream fin = new FileInputStream(file)) {
            store.load(fin, password);
        }
        return store;
    }

    /**
     * Tries to determine the path to the default cacerts truststore used by the JVM.
     * Resolution order:
     * 1) javax.net.ssl.trustStore system property (if set)
     * 2) Common default locations relative to java.home (JDK 9+/11+: lib/security/cacerts, JDK 8: jre/lib/security/cacerts, some builds: conf/security/cacerts)
     * Returns null if not found.
     */
    public static String findCacertsPath() {
        String trustStoreProp = System.getProperty("javax.net.ssl.trustStore");
        if (trustStoreProp != null && !trustStoreProp.isEmpty()) {
            return Paths.get(trustStoreProp).toAbsolutePath().toString();
        }
        String javaHome = System.getProperty("java.home");
        if (javaHome == null || javaHome.isEmpty()) return null;

        Path[] candidates = new Path[] {
                Paths.get(javaHome, "lib", "security", "cacerts"),
                Paths.get(javaHome, "jre", "lib", "security", "cacerts"),
                Paths.get(javaHome, "conf", "security", "cacerts")
        };
        for (Path p : candidates) {
            if (Files.isRegularFile(p)) {
                return p.toAbsolutePath().toString();
            }
        }
        return null;
    }
}
