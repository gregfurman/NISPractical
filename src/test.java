import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.util.Arrays;

public class test {

    public static void main(String[] args){

        try {

            CertificateAuthority ca = new CertificateAuthority();
//            CertificateAuthority ca2 = new CertificateAuthority();

            Cryptography crypto = new Cryptography();

//            String message = "hello";

            SecretKey key = crypto.generateSecretKey();

            byte[] encryptedKey = EncryptSecretKey(ca,key);

            System.out.println(decryptAESKey(encryptedKey,ca).equals(key));

        } catch (Exception e){
            e.printStackTrace();
        }


    }

    private static byte[] EncryptSecretKey (CertificateAuthority ca, SecretKey skey)
    {
        Cipher cipher = null;
        byte[] key = null;

        try
        {
            // initialize the cipher with the user's public key
            cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, ca.getPublic() );
            key = cipher.doFinal(skey.getEncoded());
        }
        catch(Exception e )
        {
            System.out.println ( "exception encoding key: " + e.getMessage() );
            e.printStackTrace();
        }
        return key;
    }

    private static SecretKey decryptAESKey(byte[] data, CertificateAuthority ca )
    {
        SecretKey key = null;
        PrivateKey privKey = null;
        Cipher cipher = null;

        try
        {
            // this is OUR private key
            privKey = ca.getPrivate();

            // initialize the cipher...
            cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, privKey );

            // generate the aes key!
            key = new SecretKeySpec( cipher.doFinal(data), "AES" );
        }
        catch(Exception e)
        {
            System.out.println ( "exception decrypting the aes key: "
                    + e.getMessage() );
            return null;
        }

        return key;
    }

}
