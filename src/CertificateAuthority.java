import java.security.*;

public class CertificateAuthority {

    private final int KEYSIZE = 2048;
    private final String ALGORITHM = "RSA";
    private final KeyPair keyPair;

    public CertificateAuthority() throws NoSuchAlgorithmException{

        this.keyPair = generateKeys();

    }

    private KeyPair generateKeys() throws NoSuchAlgorithmException {

        KeyPairGenerator keypair = KeyPairGenerator.getInstance(ALGORITHM);
        keypair.initialize(KEYSIZE);
        return keypair.generateKeyPair();
    }

    public PublicKey getPublic(){
        return keyPair.getPublic();
    }

    public PrivateKey getPrivate(){
        return keyPair.getPrivate();
    }
}