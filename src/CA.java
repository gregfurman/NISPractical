import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import sun.security.x509.*;
import java.security.cert.*;
import java.util.Date;

public class CA {


    private PublicKey publicKey;
    private PrivateKey privateKey;
    private CertificateAuthority CA;

    /**
     * Constructor method for the certificate authority.
     * Generates its own public and private keys.
     * @throws NoSuchAlgorithmException
     */
    public CA() throws NoSuchAlgorithmException {
        CA = new CertificateAuthority();
        this.publicKey = CA.getPublic();
        this.privateKey = CA.getPrivate();

    }

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
    public X509Certificate createCertificate(String senderName, PublicKey senderPubKey) throws IOException, CertificateException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
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
        certificate.sign(this.privateKey, rsa.getName());

        return certificate;
    }

}