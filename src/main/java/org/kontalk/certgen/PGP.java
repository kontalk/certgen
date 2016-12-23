/*
 * Kontalk Android client
 * Copyright (C) 2014 Kontalk Devteam <devteam@kontalk.org>

 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package org.kontalk.certgen;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;
import java.util.Iterator;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.*;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;


/** Some PGP utility method, mainly for use by {@link PersonalKey}. */
public class PGP {

    /** Security provider: Spongy Castle. */
    public static final String PROVIDER = "BC";

    /** Default EC curve used. */
    private static final String EC_CURVE = "P-256";

    /** Default RSA key length used. */
    private static final int RSA_KEY_LENGTH = 2048;

    /** Singleton for converting a PGP key to a JCA key. */
    private static JcaPGPKeyConverter sKeyConverter;

    static KeyFingerPrintCalculator sFingerprintCalculator =
        new BcKeyFingerprintCalculator();

    private PGP() {
    }

    public static final class PGPDecryptedKeyPairRing {
        /* Authentication key. */
        PGPKeyPair authKey;
        /* Signing key. */
        PGPKeyPair signKey;
        /* Encryption key. */
        PGPKeyPair encryptKey;

        public PGPDecryptedKeyPairRing(PGPKeyPair auth, PGPKeyPair sign, PGPKeyPair encrypt) {
            this.authKey = auth;
            this.signKey = sign;
            this.encryptKey = encrypt;
        }
    }

    public static final class PGPKeyPairRing {
        public PGPPublicKeyRing publicKey;
        public PGPSecretKeyRing secretKey;

        PGPKeyPairRing(PGPPublicKeyRing publicKey, PGPSecretKeyRing secretKey) {
            this.publicKey = publicKey;
            this.secretKey = secretKey;
        }

        public static PGPKeyPairRing load(byte[] privateKeyData, byte[] publicKeyData)
                throws IOException, PGPException {
            ArmoredInputStream inPublic = new ArmoredInputStream(new ByteArrayInputStream(publicKeyData));
            PGPPublicKeyRing publicKey = new PGPPublicKeyRing(inPublic, sFingerprintCalculator);
            ArmoredInputStream inPrivate = new ArmoredInputStream(new ByteArrayInputStream(privateKeyData));
            PGPSecretKeyRing secretKey = new PGPSecretKeyRing(inPrivate, sFingerprintCalculator);
            return new PGPKeyPairRing(publicKey, secretKey);
        }
    }

    public static void registerProvider() {
        // register spongy castle provider
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
    }

    /** Creates an ECDSA/ECDH key pair. */
    public static PGPDecryptedKeyPairRing create()
            throws NoSuchAlgorithmException, NoSuchProviderException, PGPException, InvalidAlgorithmParameterException {

        KeyPairGenerator gen;
        PGPKeyPair authKp, encryptKp, signKp;

        gen = KeyPairGenerator.getInstance("RSA", PROVIDER);
        gen.initialize(RSA_KEY_LENGTH);

        authKp = new JcaPGPKeyPair(PGPPublicKey.RSA_GENERAL, gen.generateKeyPair(), new Date());

        gen = KeyPairGenerator.getInstance("ECDH", PROVIDER);
        gen.initialize(new ECGenParameterSpec(EC_CURVE));

        encryptKp = new JcaPGPKeyPair(PGPPublicKey.ECDH, gen.generateKeyPair(), new Date());

        gen = KeyPairGenerator.getInstance("ECDSA", PROVIDER);
        gen.initialize(new ECGenParameterSpec(EC_CURVE));

        signKp = new JcaPGPKeyPair(PGPPublicKey.ECDSA, gen.generateKeyPair(), new Date());

        return new PGPDecryptedKeyPairRing(authKp, signKp, encryptKp);
    }

    /** Creates public and secret keyring for a given keypair. */
    public static PGPKeyPairRing store(PGPDecryptedKeyPairRing pair,
            String id,
            String passphrase)
        throws PGPException, IOException {

        PGPSignatureSubpacketGenerator sbpktGen;

        // some hashed subpackets for the key
        sbpktGen = new PGPSignatureSubpacketGenerator();
        // the master key is used for authentication and certification
        sbpktGen.setKeyFlags(false, PGPKeyFlags.CAN_AUTHENTICATE | PGPKeyFlags.CAN_CERTIFY);
        sbpktGen.setPrimaryUserID(false, true);

        PGPDigestCalculator digestCalc = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);
        PGPKeyRingGenerator keyRingGen = new PGPKeyRingGenerator(PGPSignature.POSITIVE_CERTIFICATION, pair.authKey,
            id, digestCalc, sbpktGen.generate(), null,
            new JcaPGPContentSignerBuilder(pair.authKey.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA256),
            new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256, digestCalc)
                .setProvider(PROVIDER).build(passphrase.toCharArray()));

        // add signing subkey
        sbpktGen = new PGPSignatureSubpacketGenerator();
        sbpktGen.setKeyFlags(false, PGPKeyFlags.CAN_SIGN);
        sbpktGen.setEmbeddedSignature(false, crossCertify(pair.signKey, pair.authKey.getPublicKey()));
        keyRingGen.addSubKey(pair.signKey, sbpktGen.generate(), null);

        // add encryption subkey
        sbpktGen = new PGPSignatureSubpacketGenerator();
        sbpktGen.setKeyFlags(false, PGPKeyFlags.CAN_ENCRYPT_COMMS);
        keyRingGen.addSubKey(pair.encryptKey, sbpktGen.generate(), null);

        PGPSecretKeyRing secRing = keyRingGen.generateSecretKeyRing();
        PGPPublicKeyRing pubRing = keyRingGen.generatePublicKeyRing();

        return new PGPKeyPairRing(pubRing, secRing);
    }

    /** Signs a public key with the given secret key. */
    public static PGPPublicKey signPublicKey(PGPKeyPair secret, PGPPublicKey keyToBeSigned, String id)
            throws PGPException, IOException, SignatureException {

        return signPublicKey(secret, keyToBeSigned, id, PGPSignature.DEFAULT_CERTIFICATION);
    }

    /** Signs a public key with the given secret key. */
    public static PGPPublicKey signPublicKey(PGPKeyPair secret, PGPPublicKey keyToBeSigned, String id, int certification)
            throws PGPException, IOException, SignatureException {

        PGPPrivateKey pgpPrivKey = secret.getPrivateKey();

        PGPSignatureGenerator       sGen = new PGPSignatureGenerator(
                new JcaPGPContentSignerBuilder(secret.getPublicKey().getAlgorithm(),
                        PGPUtil.SHA512).setProvider(PROVIDER));

        sGen.init(certification, pgpPrivKey);

        return PGPPublicKey.addCertification(keyToBeSigned, id, sGen.generateCertification(id, keyToBeSigned));
    }

    /** Generates a cross-certification for a subkey. */
    private static PGPSignature crossCertify(PGPKeyPair signer, PGPPublicKey key) throws PGPException {
        PGPSignatureGenerator sGen = new PGPSignatureGenerator(
            new JcaPGPContentSignerBuilder(signer.getPublicKey().getAlgorithm(),
                PGPUtil.SHA256).setProvider(PROVIDER));
        sGen.init(PGPSignature.PRIMARYKEY_BINDING, signer.getPrivateKey());
        return sGen.generateCertification(key);
    }

    /** Revokes the given key. */
    public static PGPPublicKey revokeKey(PGPKeyPair secret)
            throws PGPException, IOException, SignatureException {

        PGPPrivateKey pgpPrivKey = secret.getPrivateKey();
        PGPPublicKey pgpPubKey = secret.getPublicKey();

        PGPSignatureGenerator       sGen = new PGPSignatureGenerator(
            new JcaPGPContentSignerBuilder(secret.getPublicKey().getAlgorithm(),
                PGPUtil.SHA256).setProvider(PROVIDER));

        sGen.init(PGPSignature.KEY_REVOCATION, pgpPrivKey);

        return PGPPublicKey.addCertification(pgpPubKey, sGen.generateCertification(pgpPubKey));
    }

    /** Returns the first user ID on the key that matches the given hostname. */
    public static String getUserId(PGPPublicKey key, String host) {
        String first = null;

        @SuppressWarnings("unchecked")
        Iterator<String> uids = key.getUserIDs();
        while (uids.hasNext()) {
            String uid = uids.next();
            // save the first if everything else fails
            if (first == null) {
                first = uid;
                // no host to verify, exit now
                if (host == null)
                    break;
            }

            if (uid != null) {
                // parse uid
                PGPUserID parsed = PGPUserID.parse(uid);
                if (parsed != null) {
                    String email = parsed.getEmail();
                    if (email != null) {
                        // check if email host name matches
                        if (host.equalsIgnoreCase(XmppStringUtils.parseDomain(email))) {
                            return uid;
                        }
                    }
                }
            }
        }

        return first;
    }

    /** Returns the first user ID on the key that matches the given hostname. */
    public static String getUserId(byte[] publicKeyring, String host) throws IOException, PGPException {
        PGPPublicKey pk = getMasterKey(publicKeyring);
        return getUserId(pk, host);
    }

    public static PGPUserID parseUserId(byte[] publicKeyring, String host) throws IOException, PGPException {
        return parseUserId(getMasterKey(publicKeyring), host);
    }

    public static PGPUserID parseUserId(PGPPublicKey key, String host) throws IOException, PGPException {
        String uid = getUserId(key, host);
        return PGPUserID.parse(uid);
    }

    public static int getKeyFlags(PGPPublicKey key) {
        @SuppressWarnings("unchecked")
        Iterator<PGPSignature> sigs = key.getSignatures();
        while (sigs.hasNext()) {
            PGPSignature sig = sigs.next();
            if (sig != null) {
                PGPSignatureSubpacketVector subpackets = sig.getHashedSubPackets();
                if (subpackets != null) {
                    return subpackets.getKeyFlags();
                }
            }
        }
        return 0;
    }

    /** Returns the first master key found in the given public keyring. */
    public static PGPPublicKey getMasterKey(PGPPublicKeyRing publicKeyring) {
        @SuppressWarnings("unchecked")
        Iterator<PGPPublicKey> iter = publicKeyring.getPublicKeys();
        while (iter.hasNext()) {
            PGPPublicKey pk = iter.next();
            if (pk.isMasterKey())
                return pk;
        }

        return null;
    }

    /** Returns the first master key found in the given public keyring. */
    public static PGPPublicKey getMasterKey(byte[] publicKeyring) throws IOException, PGPException {
        return getMasterKey(readPublicKeyring(publicKeyring));
    }

    public static PGPPublicKey getSigningKey(PGPPublicKeyRing publicKeyring) {
        @SuppressWarnings("unchecked")
        Iterator<PGPPublicKey> iter = publicKeyring.getPublicKeys();
        while (iter.hasNext()) {
            PGPPublicKey pk = iter.next();
            if (!pk.isMasterKey()) {
                int keyFlags = getKeyFlags(pk);
                if ((keyFlags & PGPKeyFlags.CAN_SIGN) == PGPKeyFlags.CAN_SIGN)
                    return pk;
            }
        }

        // legacy key format support
        return getLegacySigningKey(publicKeyring);
    }

    public static PGPPublicKey getEncryptionKey(PGPPublicKeyRing publicKeyring) {
        @SuppressWarnings("unchecked")
        Iterator<PGPPublicKey> iter = publicKeyring.getPublicKeys();
        while (iter.hasNext()) {
            PGPPublicKey pk = iter.next();
            if (!pk.isMasterKey()) {
                int keyFlags = getKeyFlags(pk);
                if ((keyFlags & PGPKeyFlags.CAN_ENCRYPT_COMMS) == PGPKeyFlags.CAN_ENCRYPT_COMMS)
                    return pk;

            }
        }

        // legacy key format support
        return getLegacyEncryptionKey(publicKeyring);
    }

    private static PGPPublicKey getLegacyEncryptionKey(PGPPublicKeyRing publicKeyring) {
        @SuppressWarnings("unchecked")
        Iterator<PGPPublicKey> iter = publicKeyring.getPublicKeys();
        while (iter.hasNext()) {
            PGPPublicKey pk = iter.next();
            if (!pk.isMasterKey() && pk.isEncryptionKey())
                return pk;
        }

        return null;
    }

    private static PGPPublicKey getLegacySigningKey(PGPPublicKeyRing publicKeyring) {
        @SuppressWarnings("unchecked")
        Iterator<PGPPublicKey> iter = publicKeyring.getPublicKeys();
        while (iter.hasNext()) {
            PGPPublicKey pk = iter.next();
            if (pk.isMasterKey())
                return pk;
        }

        return null;
    }

    public static PGPPublicKeyRing readPublicKeyring(byte[] publicKeyring) throws IOException, PGPException {
        PGPObjectFactory reader = new PGPObjectFactory(publicKeyring, sFingerprintCalculator);
        Object o = reader.nextObject();
        while (o != null) {
            if (o instanceof PGPPublicKeyRing)
                return (PGPPublicKeyRing) o;

            o = reader.nextObject();
        }

        throw new PGPException("invalid keyring data.");
    }

    private static void ensureKeyConverter() {
        if (sKeyConverter == null)
            sKeyConverter = new JcaPGPKeyConverter().setProvider(PGP.PROVIDER);
    }

    public static PrivateKey convertPrivateKey(PGPPrivateKey key) throws PGPException {
        ensureKeyConverter();
        return sKeyConverter.getPrivateKey(key);
    }

    @SuppressWarnings("unchecked")
    public static PrivateKey convertPrivateKey(byte[] privateKeyData, String passphrase)
            throws PGPException, IOException {

        PGPDigestCalculatorProvider digestCalc = new JcaPGPDigestCalculatorProviderBuilder().build();
        PBESecretKeyDecryptor decryptor = new JcePBESecretKeyDecryptorBuilder(digestCalc)
            .setProvider(PGP.PROVIDER)
            .build(passphrase.toCharArray());

        // load the secret key ring
        PGPSecretKeyRing secRing = new PGPSecretKeyRing(privateKeyData, sFingerprintCalculator);

        // search and decrypt the master (signing key)
        // secret keys
        Iterator<PGPSecretKey> skeys = secRing.getSecretKeys();
        while (skeys.hasNext()) {
            PGPSecretKey key = skeys.next();
            PGPSecretKey sec = secRing.getSecretKey();

            if (key.isMasterKey())
                return convertPrivateKey(sec.extractPrivateKey(decryptor));
        }

        throw new PGPException("no suitable private key found.");
    }

    public static PublicKey convertPublicKey(PGPPublicKey key) throws PGPException {
        ensureKeyConverter();
        return sKeyConverter.getPublicKey(key);
    }

    public static PGPSecretKeyRing copySecretKeyRingWithNewPassword(byte[] privateKeyData,
            String oldPassphrase, String newPassphrase) throws PGPException, IOException {

        // load the secret key ring
        PGPSecretKeyRing secRing = new PGPSecretKeyRing(privateKeyData, sFingerprintCalculator);

        return copySecretKeyRingWithNewPassword(secRing, oldPassphrase, newPassphrase);
    }

    public static PGPSecretKeyRing copySecretKeyRingWithNewPassword(PGPSecretKeyRing secRing,
            String oldPassphrase, String newPassphrase) throws PGPException {

        PGPDigestCalculatorProvider digestCalcProv = new JcaPGPDigestCalculatorProviderBuilder().build();
        PBESecretKeyDecryptor decryptor = new JcePBESecretKeyDecryptorBuilder(digestCalcProv)
            .setProvider(PGP.PROVIDER)
            .build(oldPassphrase.toCharArray());

        PGPDigestCalculator digestCalc = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA256);
        PBESecretKeyEncryptor encryptor = new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256, digestCalc)
            .setProvider(PROVIDER).build(newPassphrase.toCharArray());

        return PGPSecretKeyRing.copyWithNewPassword(secRing, decryptor, encryptor);
    }

}
