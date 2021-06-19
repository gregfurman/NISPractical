import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.lang.reflect.Array;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.Inflater;
import java.util.zip.InflaterOutputStream;


public class Client {

    private static int BUFFERSIZE = 2048;

    private final Socket clientSocket;

    private final DataInputStream input;
    private final DataOutputStream output;
    private final BufferedReader keyboardInput;

    private Cryptography crypto;


    public static void main(String[] args){

        try {
            Client client = new Client("127.0.0.1", 6666);

            client.start();

        } catch (IOException e){
            System.out.println("No server found.");
        }  catch (NoSuchAlgorithmException a){
            System.out.println("Fatal error: RSA key pairs failed to load/generate.");
        }

    }


    public Client(String address,int portNumber) throws IOException, NoSuchAlgorithmException {

        crypto = new Cryptography();
        clientSocket = new Socket(address, portNumber);

        output = new DataOutputStream(clientSocket.getOutputStream());
        input = new DataInputStream(clientSocket.getInputStream());

        keyboardInput = new BufferedReader(new InputStreamReader(System.in));

    }



    private Thread receiverThread() {

        return new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    byte[] byteArray;
                    // While loop that blocks on the receiveByres method.
                    while ((byteArray = receiveBytes()) != null) {

                        // Decryption!!
                        System.out.println(new String(decryptMessage(byteArray)));

                    }

                    clientSocket.close();

                } catch (IOException e) {
                    System.out.println("Client disconnected.");
                    e.printStackTrace();

                } catch (Exception e) {
                    System.out.println("Fatal error: decryption failed.");
                    e.printStackTrace();
                }

                System.exit(0);
            }
        });
    }

    private Thread senderThread(){

        return new Thread(new Runnable() {
            @Override
            public void run() {

                try {
                    String message;

                    while (!(message = keyboardInput.readLine()).equals("quit")) {

                        sendBytes(encryptMessage(message));

                    }

                } catch (Exception e) {
                    e.printStackTrace();
                }

                System.exit(0);
            }
        });


    }

    public void start(){

        try {

            //Creates a certificate and sends it to server
            X509Certificate myID = CA.createCertificate("CN=BOB, C=CapeTown, C=ZA", crypto.getPublicKey());
            System.out.println("Sending Alice my certificate (I'm Bob) ");
            sendBytes(myID.getEncoded());

            // Received bytes from server and converts it to a certificate
            byte [] senderCertificate = receiveBytes();
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            ByteArrayInputStream aliceCertificate = new ByteArrayInputStream(senderCertificate);
            Certificate certificate = cf.generateCertificate(aliceCertificate);
            System.out.println("Received alice's certificate");

            // Retrieves authorities public key and verifies the certificate
            PublicKey AuthorityPubKey = CA.getPublicKey();
            certificate.verify(AuthorityPubKey);
            System.out.println("Verified alice's certificate");

            // Retrieves server public key from the certificate and saves it.
            crypto.setKUb(certificate.getPublicKey().getEncoded());
            System.out.println("Received alice's public key");


        
        } catch (Exception e){
            System.out.println("Failed to send Certificate.");
            e.printStackTrace();
        }

        Thread sender = senderThread();
        Thread receiver = receiverThread();

        sender.start();
        receiver.start();


    }

    /**
     * Method to encrypt a string message using AES ecnryption with an ephemeral session key and
     * initialisation vector. The resulting message, key, and IV are sent as bytes to the client.
     * @param message String message to encrypted and sent to client.
     */
    private byte[] encryptMessage(String message) throws Exception {

        // Session key component
        ByteArrayOutputStream SessionKeyComponent = new ByteArrayOutputStream();

        byte[] recipientPublicKey = crypto.getReceipientKey().getEncoded();
        System.out.println("Public key object length: " + recipientPublicKey.length);
        SessionKeyComponent.write(recipientPublicKey);

        SecretKey key = crypto.generateSecretKey();
        byte[] encryptedKey = crypto.encryptSecretKey(key);
        SessionKeyComponent.write(encryptedKey);
        System.out.println("Session key length: " + encryptedKey.length);

        // adding init vector - maybe encrypt?
        IvParameterSpec iv = crypto.generateInitialisationVector();
        SessionKeyComponent.write(iv.getIV());
        System.out.println("IV length: " + iv.getIV().length);


        // Signature
        ByteArrayOutputStream Signature = new ByteArrayOutputStream();

        // converting hash of datetime to 32 byte array
        Date today = new Date();
        byte[] timeStamp = ByteBuffer.allocate(32).putInt(new Date(today.getTime() + 100).hashCode()).array();
        Signature.write(timeStamp);

        byte[] myPublicKey = crypto.getPublicKey().getEncoded();
        Signature.write(myPublicKey);

        byte[] messageDigest = crypto.privateKeyEncrypt(crypto.sha512(message.getBytes()));
        System.out.println("Message digest length: " + messageDigest.length);
        byte[] leadingOctets = Arrays.copyOfRange(messageDigest, 0, 2);
        Signature.write(leadingOctets);

        Signature.write(messageDigest);

        // Message
        ByteArrayOutputStream Message = new ByteArrayOutputStream();
        Message.write(message.getBytes());

        // Adding message byte array to end of signature for compression
        Signature.write(Message.toByteArray());

        byte[] compressedAndEncryptedMessage = crypto.encryptWithSecretKey(compress(Signature.toByteArray()), key, iv); // Here is where compression takes place.

        ByteArrayOutputStream PGPMessage = new ByteArrayOutputStream();
        PGPMessage.write(SessionKeyComponent.toByteArray());
        PGPMessage.write(compressedAndEncryptedMessage);


        return Base64.getEncoder().encode(PGPMessage.toByteArray());


    }

    private byte[] decryptMessage(byte[] rawMessageData) throws Exception{

        byte[] decodedData = Base64.getDecoder().decode(rawMessageData);
        // Length of byte array of public key object in java is 294 bytes. Go figure.

        // Session component
        byte[] publicKey = Arrays.copyOfRange(decodedData,0,294);

        if (!crypto.isPublicKey(publicKey))
            throw new Exception("Destination ID is incorrect.");

        SecretKey key = crypto.decryptSecretKey(Arrays.copyOfRange(decodedData,294,550));
        IvParameterSpec iv = new IvParameterSpec(Arrays.copyOfRange(decodedData,550,566)); // Maybe decrypt?

        // Signature

        byte[] data = decompress(crypto.decryptWithSecretKey(Arrays.copyOfRange(decodedData,566,decodedData.length),key,iv));

        int bytesRead = 0;

        Date timestamp = new Date(new BigInteger(Arrays.copyOfRange(data,bytesRead, bytesRead+4)).intValue());
        bytesRead+= 4;
        Date now = new Date();
        long SecondsToArrive= ((now.getTime()- timestamp.getTime() )/1000)%60;
        System.out.println(now.toString() + " " + timestamp.toString());

        // If takes longer than 60 seconds timeout
        if (SecondsToArrive > 60)
            throw new Exception(String.format("Time to live of message has expired: took %d seconds.",SecondsToArrive));

        // Get public key of sender
        byte[] senderPublicKey = Arrays.copyOfRange(data,bytesRead,bytesRead + 294);
        if (!crypto.isSendersPublicKey(senderPublicKey))
            throw new Exception("Sender ID is incorrect.");
        bytesRead+=294; // length of public key object encoding

        // No idea what to do with the octets but it's in the PGP message sooooo
        byte[] octets = Arrays.copyOfRange(data,bytesRead,bytesRead+2); // ???
        bytesRead+=2;

        byte[] messageDigest = crypto.PublicKeyDecryptB(Arrays.copyOfRange(data,bytesRead,bytesRead+256));
        bytesRead+=256;
//        System.out.println(new String(messageDigest,"UTF-8"));

         // Entire message
        System.out.println("start");
        if (!crypto.checkHash(Arrays.copyOfRange(data,bytesRead,data.length),messageDigest))
            throw new Exception("Integrity or authority violation: Message digest error.");
        System.out.println("end");

        System.out.println(bytesRead);
        boolean isFile =  data[bytesRead] == 1; //584
        bytesRead += 1;

        byte[] message;
        if (isFile) {

            // Length of caption string in byte form to allow for reading from data
            int captionLength = new BigInteger(Arrays.copyOfRange(data,bytesRead,bytesRead+4)).intValue();
            bytesRead+=4;

            message = Arrays.copyOfRange(data,bytesRead,captionLength+bytesRead);
            bytesRead+=captionLength;

            // Length of filename string in byte form to allow for reading from data
            int fileNameLength = new BigInteger(Arrays.copyOfRange(data,bytesRead,bytesRead+4)).intValue();
            bytesRead+=4;

            String filename =  new String(Arrays.copyOfRange(data,bytesRead,bytesRead+fileNameLength), "UTF-8");

            // Length of file used to read bytes that correspond to file
            int fileLength =  (int)ByteBuffer.wrap(Arrays.copyOfRange(data,bytesRead,bytesRead+8)).getLong();
            bytesRead+=8;

            byte[] file = Arrays.copyOfRange(data, bytesRead, bytesRead+fileLength);


            FileOutputStream fout = new FileOutputStream(filename);
            fout.write(file);
            fout.close();

        } else{
            message = Arrays.copyOfRange(data,bytesRead,data.length);
            if (!crypto.checkHash(message,messageDigest))
                throw new Exception("Integrity or authority violation: Message digest error.");
        }

        return message;
    }


    private byte[] compress(byte[] data) throws IOException{

        ByteArrayOutputStream bos = new ByteArrayOutputStream();

        Deflater deflater = new Deflater(Deflater.BEST_COMPRESSION,true);

        DeflaterOutputStream dos = new DeflaterOutputStream(bos,deflater);

        dos.write(data);

        dos.close();

        return bos.toByteArray();

    }


    private byte[] decompress(byte[] data) throws IOException{


        ByteArrayOutputStream bos = new ByteArrayOutputStream();

        Inflater inflater = new Inflater(true);

        InflaterOutputStream ios = new InflaterOutputStream(bos,inflater);

        ios.write(data);
        ios.close();

        return bos.toByteArray();

    }

    private byte[] receiveBytes() throws IOException {

        byte[] buffer = new byte[1024];

        ByteArrayOutputStream bos = new ByteArrayOutputStream();


        while (true) {
            int count = input.read(buffer);
            bos.write(buffer,0,count);
            if (input.available() == 0){
                break;
            }

        }

        return bos.toByteArray();
    }

    /**
     *
     * @param data
     * @throws IOException
     */

    private void sendBytes(byte[] data) throws IOException{

        if (data.length>0){
            output.write(data);
        }
        output.flush();
    }

}
