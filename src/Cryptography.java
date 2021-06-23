import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

public class Cryptography {

    private final int AES_BLOCK_SIZE = 32; // Size of Cipher Block Chaining block
    private final int AES_KEY_SIZE = 256; // Size of AES secret key. Larger sizes mean more security.

    final String PUBLIC_KEY_ALGORITHM = "RSA/ECB/PKCS1Padding"; // Algorithm specs for public/private key encryption/decryption
    final String MESSAGE_DIGEST_ALGORITHM = "SHA-512"; // Message Digest algorithm
    final String SECRET_KEY_ALGORITHM = "AES/CBC/PKCS5Padding"; // Algorithms specs for ephemeral key

    private PublicKey KU;
    private PrivateKey KR;
    private RSAKeyGenerator keyGen;

    private PublicKey KUb;

    /**
     * Constructor method for Cryptography object. Contains methods relating to cryptographic processes.
     * Upon instantiation, a public and private key are generated and set.
     * @throws NoSuchAlgorithmException
     */
    public Cryptography() throws NoSuchAlgorithmException{
        keyGen = new RSAKeyGenerator();
        KU = keyGen.getPublic();
        KR = keyGen.getPrivate();

    }

    /**
     * Method for setting the public key of a client to a given encoded public key.
     * @param KUb Encoded public key object.
     * @throws Exception Error thrown if public key fails to generate.
     */
    public void setKUb(byte[] KUb) throws Exception {
        this.KUb = generatePublicKey(KUb);
    }

    /**
     * Method for generating a public key from a byte array.
     * @param key encoded public key in byte array form.
     * @return PublicKey object generated from byte array.
     * @throws Exception Error thrown in key fails to successfully generate.
     */
    public PublicKey generatePublicKey(byte[] key) throws Exception{
        return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(key));
    }

    /**
     * Method for getting public key.
     * @return public key returned as PublicKey object
     */
    public PublicKey getPublicKey(){
        return KU;
    }

    /**
     * Method for getting private key.
     * @return private key returned as PrivateKey object
     */
    public PrivateKey getPrivateKey(){
        return KR;
    }

    /**
     * Method for checking if an input public key is the same as the current clients' key.
     * Used for authentication.
     * @param publicKey public key encoded as byte array.
     * @return Boolean indicating if keys are equal.
     * @throws Exception Error if key fails to generate.
     */
    public boolean isPublicKey(byte[] publicKey) throws Exception{
        return KU.equals(generatePublicKey(publicKey));
    }


    /**
     * Method for checking whether an input public key is equal to foreign public key.
     * Used for authentication.
     * @param publicKey Encoded PublicKey object.
     * @return Boolean indicating if public keys are equal.
     */
    public boolean isSendersPublicKey(byte[] publicKey){
        return Arrays.equals(publicKey,KUb.getEncoded());
    }

    /**
     * getMethod for returning a Public Key
     * @return Public Key Object
     */
    public PublicKey getReceipientKey(){
        return KUb;
    }

    /**
     * Method for generating Secret Key
     * @return  Secret Key object
     * @throws NoSuchAlgorithmException
     */

    public SecretKey generateSecretKey() throws NoSuchAlgorithmException {

        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(AES_KEY_SIZE);
        return keyGen.generateKey();

    }

    /**
     * Method for encrypting data using Secret Key
     * @param data Message/File data to be encrypted
     * @param secretKey Secret key object
     * @param iv Initiralization vector used for encryptin
     * @return  Encrypted byte array
     * @throws Exception
     */
    public byte[] encryptWithSecretKey(byte[] data, SecretKey secretKey, IvParameterSpec iv) throws Exception{

        Cipher cipher = Cipher.getInstance(SECRET_KEY_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);

        return cipher.doFinal(data);

    }

    /**
     * Method for encrypting an AES secret key with public key of foreign party.
     * @param secretKey Secret key object
     * @return Encrypted secret key object.
     * @throws Exception Error thrown if encryption error.
     */
    public byte[] encryptSecretKey(SecretKey secretKey) throws Exception{

        Cipher cipher = Cipher.getInstance(PUBLIC_KEY_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, KUb);

        return cipher.doFinal(secretKey.getEncoded());

    }

    /**
     * Method to decrypt secret key.
     * @param encodedSecretKey Encrypted secret key object as byte array.
     * @return Decrypted secret key object.
     * @throws Exception Throws if error occurs while decrypting or constructing key object
     */
    public SecretKey decryptSecretKey(byte[] encodedSecretKey) throws Exception{

        Cipher cipher = Cipher.getInstance(PUBLIC_KEY_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, KR);

        byte[] encryptedSecretKey = cipher.doFinal(encodedSecretKey);

        return new SecretKeySpec(encryptedSecretKey, 0, AES_BLOCK_SIZE, "AES");

    }

    /**
     * Method to decrypt data using a secret key.
     * @param data Data to be decrypted.
     * @param secretKey Ephemeral AES secret key object
     * @param iv Initialisation vector used for CBC decryption.
     * @return Decrypted byte array.
     * @throws Exception If error occurs while decrypting
     */
    public byte[] decryptWithSecretKey(byte[] data,SecretKey secretKey, IvParameterSpec iv)throws Exception{

        Cipher cipher = Cipher.getInstance(SECRET_KEY_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey,iv);
        return cipher.doFinal(data);

    }

    /**
     * Creates a 16 byte initialisation vector for Cipher Block Chaining encryption/decryption
     * @return initialisation vector in the form of 16 byte array.
     */
    public IvParameterSpec generateInitialisationVector() {
        byte[] IV = new byte[16];
        new SecureRandom().nextBytes(IV);
        return new IvParameterSpec(IV);
    }

    /**
     * Method to use private key to encrypt data M.
     * @param M Data to be encrypted using private key.
     * @return Encrypted byte array of M.
     * @throws Exception If decryption fails.
     */

    public byte[] privateKeyEncrypt(byte[] M) throws Exception {
        Cipher cipher = Cipher.getInstance(PUBLIC_KEY_ALGORITHM);

        cipher.init(Cipher.ENCRYPT_MODE,KR);

        return cipher.doFinal(M);

    }

    /**
     * Method to use public key of other party to decrypt data M.
     * @param M Data to be decrypted using public key of other party.
     * @return Decrypted data
     * @throws Exception If decryption fails.
     */

    public byte[] PublicKeyDecryptB(byte[] M)throws Exception{
        Cipher cipher = Cipher.getInstance(PUBLIC_KEY_ALGORITHM);

        cipher.init(Cipher.DECRYPT_MODE,KUb);

        return cipher.doFinal(M);
    }

    /**
     * Checks if a given encoded Message Digest is equal to another Message Digest.
     * @param MessageDigest1
     * @param MessageDigest2
     * @return A boolean indicating if two Message Digests are equal.
     */
    public boolean checkHash(byte[] MessageDigest1, byte[] MessageDigest2) {
        return MessageDigest.isEqual(MessageDigest1,MessageDigest2);
    }


}
