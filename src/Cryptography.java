import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;


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


    public PublicKey generatePublicKey(byte[] key) throws Exception{
        return
                KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(key));
    }

    public PublicKey getPublicKey(){
        return KU;
    }

    public PrivateKey getPrivateKey(){
        return KR;
    }

    public boolean isPublicKey(byte[] publicKey) throws Exception{
        return KU.equals(generatePublicKey(publicKey));
    }

//    public byte[]

    public boolean isSendersPublicKey(byte[] publicKey){
        return Arrays.equals(publicKey,KUb.getEncoded());
    }

    public PublicKey getReceipientKey(){
        return KUb;
    }
    public SecretKey generateSecretKey() throws NoSuchAlgorithmException {

        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        return keyGen.generateKey();

    }

    public byte[] encryptWithSecretKey(byte[] data, SecretKey secretKey, IvParameterSpec iv) throws Exception{


        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);

        return cipher.doFinal(data);


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
        return cipher.doFinal(data);

    }

    public IvParameterSpec generateInitialisationVector() {
        byte[] IV = new byte[16];
        new SecureRandom().nextBytes(IV);
        return new IvParameterSpec(IV);
    }

    public byte[] privateKeyEncrypt(byte[] M) throws Exception {
        Cipher cipher = Cipher.getInstance(CIPHER_MODE);

        cipher.init(Cipher.ENCRYPT_MODE,KR);

        return cipher.doFinal(M);

    }



    public byte[] PublicKeyDecryptB(byte[] M)throws Exception{
        Cipher cipher = Cipher.getInstance(CIPHER_MODE);

        cipher.init(Cipher.DECRYPT_MODE,KUb);

        return cipher.doFinal(M);
    }



    public byte[] sha512(byte[] data) throws Exception{

        MessageDigest digest = MessageDigest.getInstance("SHA-512");
        digest.reset();
        digest.update(data);
        return byteHex(digest.digest()).getBytes();

    }


    public byte[] sha512File(File file) throws Exception{

        MessageDigest digest = MessageDigest.getInstance("SHA-512");
        digest.reset();
        byte[] hash = new byte[0];
        try{
            BufferedInputStream bis = new BufferedInputStream(new FileInputStream(file));
            DigestInputStream dis = new DigestInputStream(bis,digest);
            while (dis.read() != -1) {
            }
            dis.close();
            hash = digest.digest();

        }

        catch(Exception e){
            System.out.println("oops");
        }

        return hash;
    }

    public String byteHex(byte[] data){
        StringBuffer hexString = new StringBuffer();
        for (int i = 0;i<data.length;i++) {
            hexString.append(Integer.toHexString(0xFF & data[i]));
        }
        return hexString.toString();
    }

    public boolean checkHash(byte[] data, byte[] received_hash) throws Exception {
        byte[] new_hash = sha512(data);
        return Arrays.equals(received_hash,new_hash);
    }

    public boolean checkHash(File file, byte[] received_hash) throws Exception {
        byte[] new_hash = sha512File(file);
        return Arrays.equals(received_hash,new_hash);
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
