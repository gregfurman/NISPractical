import java.security.*;

public class RSAKeyGenerator {

    private final int KEYSIZE = 2048;
    private final String ALGORITHM = "RSA";
    private final KeyPair keyPair;

    /**
     * Constructor for RSA key generator.
     * @throws NoSuchAlgorithmException Error if specified key generation algorithm does not exist.
     */
    public RSAKeyGenerator() throws NoSuchAlgorithmException{

        this.keyPair = generateKeys();

    }

    /**
     * Method to generate public-private key-pair.
     * @return KeyPair object
     * @throws NoSuchAlgorithmException Error if algorithm for key generation does not exist.
     */
    private KeyPair generateKeys() throws NoSuchAlgorithmException {

        KeyPairGenerator keypair = KeyPairGenerator.getInstance(ALGORITHM);
        keypair.initialize(KEYSIZE);
        return keypair.generateKeyPair();
    }

    /**
     * Method to get public key from key generator.
     * @return PublicKey object
     */
    public PublicKey getPublic(){
        return keyPair.getPublic();
    }

    /**
     * Method to get private key object from key generator
     * @return PrivateKey object
     */
    public PrivateKey getPrivate(){
        return keyPair.getPrivate();
    }
}