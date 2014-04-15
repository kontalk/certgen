package org.kontalk.certgen;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Iterator;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
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
import org.kontalk.certgen.PGP.PGPDecryptedKeyPairRing;

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

    private PGPDecryptedKeyPairRing serverKeyPair;
    private PGPDecryptedKeyPairRing userKeyPair;

    public static void log(String fmt, Object... args) {
        System.err.println(String.format(fmt, args));
    }

    private void loadServerKeys() throws FileNotFoundException, IOException, PGPException {
        KeyFingerPrintCalculator fpr = new BcKeyFingerprintCalculator();
        PGPSecretKeyRing secRing = new PGPSecretKeyRing(new ArmoredInputStream(new FileInputStream(serverSecretKeyring)), fpr);
        PGPPublicKeyRing pubRing = new PGPPublicKeyRing(new ArmoredInputStream(new FileInputStream(serverPublicKeyring)), fpr);

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

    private void signUserKey() {
        // TODO
    }

    private void createBridgeCert() {
        // TODO
    }

    private boolean validate(JCommander args) {
        if (serverSecretKeyring == null || serverPublicKeyring == null)
            return false;

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

        // sign user key with server key
        signUserKey();

        // generate bridge certificate and sign it
        createBridgeCert();

        // TODO
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
