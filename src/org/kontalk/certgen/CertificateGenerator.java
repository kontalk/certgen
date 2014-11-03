package org.kontalk.certgen;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Iterator;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPKeyRing;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.operator.OperatorCreationException;
import org.kontalk.certgen.PGP.PGPDecryptedKeyPairRing;
import org.kontalk.certgen.PGP.PGPKeyPairRing;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;


/**
 * The Kontalk login certificate generator.
 * @author Daniele Ricci
 */
public class CertificateGenerator {

    @Parameter(names = "--gen-key", description = "Generate a new key")
    public boolean generateKey = true;

    @Parameter(names = "--server-key", description = "Path to the server secret key file")
    public String serverSecretKeyring;

    @Parameter(names = "--server-pass", description = "Passphrase to the server secret key")
    public String serverPassphrase = "";

    @Parameter(names = "--server-cert", description = "Path to the server public key file")
    public String serverPublicKeyring;

    @Parameter(names = "--userid", description = "PGP user ID (format: name <email> (comment)")
    public String userId;

    @Parameter(names = "--passphrase", description = "PGP user passphrase (default: random)")
    public String userPassphrase;

    @Parameter(names = "--out-privatekey", description = "Path to save PGP secret key")
    public String userSecretKeyring = "privatekey.asc";

    @Parameter(names = "--out-publickey", description = "Path to save PGP public key")
    public String userPublicKeyring = "publickey.asc";

    @Parameter(names = "--out-logincert", description = "Path to save X.509 bridge certificate")
    public String userBridgeCert = "login.crt";

    @Parameter(names = "--out-loginkey", description = "Path to save X.509 bridge key")
    public String userBridgeKey = "login.key";

    private PGPDecryptedKeyPairRing serverKeyPair;
    private PGPDecryptedKeyPairRing userKeyPair;

    private PGPKeyPairRing userStoredKeypair;

    private X509Certificate bridgeCert;
    private PrivateKey bridgeKey;

    public static void log(String fmt, Object... args) {
        System.err.println(String.format(fmt, args));
    }

    /** Loads the server keys internally. */
    @SuppressWarnings("unchecked")
    private void loadServerKeys() throws FileNotFoundException, IOException, PGPException {
        KeyFingerPrintCalculator fpr = new BcKeyFingerprintCalculator();
        PGPSecretKeyRing secRing = new PGPSecretKeyRing(new ArmoredInputStream(new FileInputStream(serverSecretKeyring)), fpr);
        PGPPublicKeyRing pubRing = new PGPPublicKeyRing(new ArmoredInputStream(new FileInputStream(serverPublicKeyring)), fpr);
        // we don't care closing the streams :)

        PGPDigestCalculatorProvider sha1Calc = new JcaPGPDigestCalculatorProviderBuilder().build();
        PBESecretKeyDecryptor decryptor = new JcePBESecretKeyDecryptorBuilder(sha1Calc)
            .setProvider(PGP.PROVIDER)
            .build(serverPassphrase.toCharArray());

        PGPKeyPair signKp, encryptKp;

        PGPPublicKey  signPub = null;
        PGPPrivateKey signPriv = null;
        PGPPublicKey   encPub = null;
        PGPPrivateKey  encPriv = null;

        // public keys
		Iterator<PGPPublicKey> pkeys = pubRing.getPublicKeys();
        while (pkeys.hasNext()) {
            PGPPublicKey key = pkeys.next();
            if (key.isMasterKey()) {
                // master (signing) key
                signPub = key;
            }
            else {
                // sub (encryption) key
                encPub = key;
            }
        }

        // secret keys
		Iterator<PGPSecretKey> skeys = secRing.getSecretKeys();
        while (skeys.hasNext()) {
            PGPSecretKey key = skeys.next();
            PGPSecretKey sec = secRing.getSecretKey();
            if (key.isMasterKey()) {
                // master (signing) key
                signPriv = sec.extractPrivateKey(decryptor);
            }
            else {
                // sub (encryption) key
                encPriv = sec.extractPrivateKey(decryptor);
            }
        }

        if (encPriv != null && encPub != null && signPriv != null && signPub != null) {
            signKp = new PGPKeyPair(signPub, signPriv);
            encryptKp = new PGPKeyPair(encPub, encPriv);
        }
        else {
            throw new PGPException("invalid key data");
        }

        serverKeyPair = new PGPDecryptedKeyPairRing(signKp, encryptKp);
    }

    /** Creates self-signed keys and all the keyring data. */
    private void createKeyRings() throws PGPException {
    	userStoredKeypair = PGP.store(userKeyPair, userId, userPassphrase);
    }

    /** Signs the user key with the server key. */
    private void signUserKey() throws SignatureException, PGPException, IOException {
    	PGPPublicKey signed = PGP.signPublicKey(serverKeyPair.signKey,
    		userStoredKeypair.publicKey.getPublicKey(), userId);

    	userStoredKeypair.publicKey = PGPPublicKeyRing
    		.insertPublicKey(userStoredKeypair.publicKey, signed);
    }

    /** Creates the X.509 bridge certificate and key. */
    private void createBridgeCert()
    		throws InvalidKeyException, IllegalStateException,
    		NoSuchAlgorithmException, SignatureException,
    		CertificateException, NoSuchProviderException,
    		PGPException, IOException, OperatorCreationException {

    	bridgeCert = X509Bridge
    		.createCertificate(userStoredKeypair.publicKey,
    		userKeyPair.signKey.getPrivateKey(), null);

    	bridgeKey = PGP.convertPrivateKey(userKeyPair.signKey.getPrivateKey());
    }

    /** Writes everything to files. */
    private void writeFiles() throws IOException {

    	// public keyring
    	writeKeyring(userStoredKeypair.publicKey, userPublicKeyring);

    	// secret keyring
    	writeKeyring(userStoredKeypair.secretKey, userSecretKeyring);

    	// bridge certificate
    	writePEM(bridgeCert, userBridgeCert);

    	// bridge key
    	writePEM(bridgeKey, userBridgeKey);
    }

    private void writeKeyring(PGPKeyRing keyring, String filename) throws IOException {
    	OutputStream out = new ArmoredOutputStream(new FileOutputStream(filename));
    	keyring.encode(out);
    	out.close();
    }

    private void writePEM(Object object, String filename) throws IOException {
    	PEMWriter writer = new PEMWriter(new FileWriter(filename));
    	writer.writeObject(object);
    	writer.close();
    }

    private boolean validate(JCommander args) {
        if (userId == null || serverSecretKeyring == null || serverPublicKeyring == null)
            return false;

        if (userPassphrase == null) {
        	userPassphrase = RandomString.generate(20);
        	log("Generating random passphrase: %s", userPassphrase);
        }

        // TODO
        return true;
    }

    private int run() throws Exception {
        PGP.registerProvider();

        // load server keys
        loadServerKeys();
        log("Server key loaded.");

        if (generateKey) {

            userKeyPair = PGP.create();

        }
        else {
            // TODO use existing key
        }

        // create keyrings
        log("Creating keyrings.");
        createKeyRings();

        // sign user key with server key
        log("Signing key.");
        signUserKey();

        // generate bridge certificate and sign it
        log("Creating X.509 bridge certificate.");
        createBridgeCert();

        // write to disk
        log("Writing keys.");
        writeFiles();

        return 0;
    }

    public static void main(String[] args) throws Exception {
        CertificateGenerator cg = new CertificateGenerator();
        JCommander argsParser = new JCommander(cg, args);
        argsParser.setProgramName("certgen");

        if (cg.validate(argsParser))
            System.exit(cg.run());
        else {
            StringBuilder buf = new StringBuilder();
            argsParser.usage(buf);
            System.err.print(buf.toString());
            System.exit(1);
        }
    }

}
