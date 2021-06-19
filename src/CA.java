import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;

import sun.security.x509.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;

public class CA {

    private static final char[] PASSWORD = {'a','v','i'};
    /**
     * Generates the certificate signed by the CA using x.509 format
     * @param senderName the ID of the sender (entity requesting the certificate)
     * @param senderPubKey the public key of the sender ((entity requesting the certificate)
     * @return X509Certificate certificate with valid information
     * @throws IOException
     * @throws CertificateException
     * @throws NoSuchProviderException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    public static X509Certificate createCertificate(String senderName, PublicKey senderPubKey) throws Exception {
        X509CertInfo certInfo = new X509CertInfo();
        Date today = new Date();
        CertificateValidity interval = new CertificateValidity(today, new Date(today.getTime() + 100));
        BigInteger serialNum = new BigInteger(64, new SecureRandom());
        X500Name owner = new X500Name(senderName); //"CN=Test, L=London, C=GB"

        certInfo.set(X509CertInfo.VALIDITY, interval);
        certInfo.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(serialNum));
        certInfo.set(X509CertInfo.SUBJECT, owner);
        certInfo.set(X509CertInfo.ISSUER, owner);
        certInfo.set(X509CertInfo.KEY, new CertificateX509Key(senderPubKey));
        certInfo.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));
        AlgorithmId rsa = new AlgorithmId(AlgorithmId.sha512WithRSAEncryption_oid);
        certInfo.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(rsa));

        X509CertImpl certificate = new X509CertImpl(certInfo);

        // Creates a keystore object
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());

        // Reads in keystore file and loads it to keystore variable
        FileInputStream inFile = new FileInputStream("AuthorityKeyStore");
        ks.load(inFile, PASSWORD);
        inFile.close();

        // retrieves the private key needed for signing the certificate
        KeyStore.ProtectionParameter protectionParam = new KeyStore.PasswordProtection(PASSWORD);
        KeyStore.PrivateKeyEntry privKeyEntry = (KeyStore.PrivateKeyEntry) ks.getEntry("CA", protectionParam);
        PrivateKey myPrivateKey = privKeyEntry.getPrivateKey();

        //Signs the certificate
        certificate.sign(myPrivateKey, rsa.getName());

        return certificate;
    }

    /**
     * Method is used to generate the self-signed certificate need for the key store. Can only be used by the CA.
     * @param senderName name of Authority
     * @param senderPubKey Authority public key
     * @param privateKey Authority private key
     * @return self-signed certificate.
     * @throws Exception
     */
    private static X509Certificate createCertificate(String senderName, PublicKey senderPubKey, PrivateKey privateKey) throws Exception {
        X509CertInfo info = new X509CertInfo();
        Date today = new Date();
        CertificateValidity interval = new CertificateValidity(today, new Date(today.getTime() + 100));
        BigInteger serialNum = new BigInteger(64, new SecureRandom());
        X500Name owner = new X500Name(senderName);

        info.set(X509CertInfo.VALIDITY, interval);
        info.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(serialNum));
        info.set(X509CertInfo.SUBJECT, owner);
        info.set(X509CertInfo.ISSUER, owner);
        info.set(X509CertInfo.KEY, new CertificateX509Key(senderPubKey));
        info.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));
        AlgorithmId rsa = new AlgorithmId(AlgorithmId.sha512WithRSAEncryption_oid);
        info.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(rsa));

        X509CertImpl certificate = new X509CertImpl(info);
        certificate.sign(privateKey, rsa.getName());

        return certificate;
    }

    /**
     * Reads in the CA public key file, converts the bytes to a public key adn returns the public key
     * @return CA public key
     * @throws Exception
     */
    public static PublicKey getPublicKey() throws Exception{
        //Reads public key file
        FileInputStream publicKeyFile = new FileInputStream("CertificateAuthorityPUB.txt");
        byte[] pubKey = new byte[publicKeyFile.available()];
        publicKeyFile.read(pubKey);
        publicKeyFile.close();

        //Converts bytes to public key variable
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(pubKey);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey =  keyFactory.generatePublic(keySpec);

        return publicKey;
    }

    /**
     * Main method run once to generate the respective private and public key pair for the Certificate Authority
     * @param args
     * @throws Exception
     */
    public static void main(String[] args) throws Exception {
        //Generates a key pair for the Certificate Authority
        CertificateAuthority CA = new CertificateAuthority();
        PrivateKey privateKey = CA.getPrivate();
        PublicKey publicKey = CA.getPublic();


        //Creates a keystore object to save the Private key and self signed certificate of the Authority
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(null, PASSWORD);

        //Generates self-signed certificate
        KeyStore.ProtectionParameter protectionParam = new KeyStore.PasswordProtection(PASSWORD);
        X509Certificate myCert = createCertificate("CN=Authority, C=CapeTown, C=ZA", publicKey, privateKey);
        Certificate[] chain = {myCert};

        //Adds private key and certificate to keystore object
        KeyStore.PrivateKeyEntry AuthorityPrivKey = new KeyStore.PrivateKeyEntry(privateKey, chain);
        keyStore.setEntry("CA", AuthorityPrivKey, protectionParam);

        //writes keystore to a file
        FileOutputStream keyStoreFile = new FileOutputStream("AuthorityKeyStore");
        keyStore.store(keyStoreFile, PASSWORD);
        keyStoreFile.close();

        //Writes authority public key to a file
        byte[] key = publicKey.getEncoded();
        FileOutputStream keyFile = new FileOutputStream("CertificateAuthorityPUB.txt");
        keyFile.write(key);
        keyFile.close();

    }

}