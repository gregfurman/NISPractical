import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.zip.GZIPInputStream;


public class Cryptography {

    private final int MAX_BLOCK_SIZE = 256;
    private final int AES_BLOCK_SIZE = 32;

    private final String CIPHER_MODE = "RSA/ECB/PKCS1Padding";

    private PublicKey KU;
    private PrivateKey KR;
    private CertificateAuthority CA;

    private PublicKey KUb;

    public Cryptography() throws NoSuchAlgorithmException{
        CA = new CertificateAuthority();
        KU = CA.getPublic();
        KR = CA.getPrivate();

    }

    public void setKUb(byte[] KUb) throws Exception {

        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(KUb);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        this.KUb =  keyFactory.generatePublic(keySpec);

    }


    public PublicKey getPublicKey(){
        return KU;
    }

    public PrivateKey getPrivateKey(){
        return KR;
    }

    public SecretKey generateSecretKey() throws NoSuchAlgorithmException {

        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        return keyGen.generateKey();

    }

    public byte[] encryptWithSecretKey(byte[] data, SecretKey secretKey, IvParameterSpec iv) throws Exception{


        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);

        return cipher.doFinal(Base64.getEncoder().encode(data));


    }


    public byte[] encryptSecretKey(SecretKey secretKey)throws Exception{

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, KUb);

        return cipher.doFinal(secretKey.getEncoded());

    }


    public SecretKey decryptSecretKey(byte[] encodedSecretKey)throws Exception{

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, KR);

        byte[] encryptedSecretKey = cipher.doFinal(encodedSecretKey);

        return new SecretKeySpec(encryptedSecretKey, 0, AES_BLOCK_SIZE, "AES");

    }

    public byte[] decryptWithSecretKey(byte[] data,SecretKey secretKey, IvParameterSpec iv)throws Exception{

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey,iv);
        return Base64.getDecoder().decode(cipher.doFinal(data));

    }

    public IvParameterSpec generateInitialisationVector() {
        byte[] IV = new byte[16];
        new SecureRandom().nextBytes(IV);
        return new IvParameterSpec(IV);
    }

    public byte[] privateKeyEncrypt(byte[] M) throws Exception {
        Cipher cipher = Cipher.getInstance(CIPHER_MODE);

        cipher.init(Cipher.ENCRYPT_MODE,KR);

        byte[] encrypted_bytes = cipher.doFinal(M);

        return Base64.getEncoder().encode(encrypted_bytes);

    }

    public byte[] publicKeyEncrypt(byte[] M) throws Exception {
        Cipher cipher = Cipher.getInstance(CIPHER_MODE);

        cipher.init(Cipher.ENCRYPT_MODE,KU);

        byte[] encrypted_bytes = cipher.doFinal(M);

        return Base64.getEncoder().encode(encrypted_bytes);

    }


    public String publicKeyEncryptB(String message) throws Exception {
        Cipher cipher = Cipher.getInstance(CIPHER_MODE);
        cipher.init(Cipher.ENCRYPT_MODE, KUb);

        byte[] data = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));

        return Base64.getEncoder().encodeToString(data);
    }

    public String privateKeyDecrypt(byte[] M) throws Exception {
        Cipher cipher = Cipher.getInstance(CIPHER_MODE);

        cipher.init(Cipher.DECRYPT_MODE,KR);
        System.out.println(M.length);

        return new String(cipher.doFinal(M),StandardCharsets.UTF_8);

    }

    public String publicKeyDecrypt(byte[] M) throws Exception {
        Cipher cipher = Cipher.getInstance(CIPHER_MODE);

        cipher.init(Cipher.DECRYPT_MODE,KR);


        return new String(cipher.doFinal(M),"UTF8");

    }

    public String sha512(byte[] M){
        // Generates hash of message
        String H = "";
        try{

            MessageDigest digest = MessageDigest.getInstance("SHA-512");
            digest.reset();
            digest.update(M);
            H = String.format("%040x", new BigInteger(1, digest.digest()));
        }
        catch(Exception E){
            System.out.println("Hash Exception");
        }
        return H;
    }




    public CipherOutputStream cipherOut( OutputStream out) throws Exception{

        Cipher cipher = Cipher.getInstance(CIPHER_MODE);
        cipher.init(Cipher.ENCRYPT_MODE, KUb);

        return new CipherOutputStream(out, cipher);

    }

    public CipherInputStream cipherInput( InputStream in) throws Exception{

        Cipher cipher = Cipher.getInstance(CIPHER_MODE);
        cipher.init(Cipher.DECRYPT_MODE, KR);
        return new CipherInputStream(in,cipher);
    }


}
