import javax.crypto.CipherInputStream;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.lang.reflect.Array;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
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
        // add in file !
        // caption jazz as well !

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

        Date timestamp = new Date(new BigInteger(Arrays.copyOfRange(data,0,32)).intValue());
        Date now = new Date();
        long SecondsToArrive= ((now.getTime()- timestamp.getTime() )/1000)%60;

        if (SecondsToArrive > 60)
            throw new Exception(String.format("Time to live of message has expired: took %d seconds.",SecondsToArrive));

        // TTL ?
        byte[] senderPublicKey = Arrays.copyOfRange(data,32,326);
        if (!crypto.isSendersPublicKey(senderPublicKey))
            throw new Exception("Sender ID is incorrect.");

        byte[] octets = Arrays.copyOfRange(data,326,328); // ???

        byte[] messageDigest = crypto.PublicKeyDecryptB(Arrays.copyOfRange(data,328,584));

        // Message Decrypt!

        boolean isFile =  data[583] == 1;
        byte[] message;
        if (true) {
            int captionLength = new BigInteger(Arrays.copyOfRange(data,584,588)).intValue();
            String caption = new String(Arrays.copyOfRange(data,588,captionLength+588), "UTF-8");
            int fileNameLength = new BigInteger(Arrays.copyOfRange(data,588+captionLength,596+captionLength)).intValue();
            String filename =  new String(Arrays.copyOfRange(data,596+captionLength,596+captionLength+fileNameLength), "UTF-8");

            long fileLength = ByteBuffer.wrap(Arrays.copyOfRange(data,596+captionLength+fileNameLength,596+captionLength+fileNameLength+8)).getLong();
            message = Arrays.copyOfRange(data, 596+captionLength+fileNameLength+8, data.length);
            if (!crypto.checkHash(message,messageDigest))
                throw new Exception("Integrity or authority violation: Message digest error.");
//            System.out.println(caption);
            FileOutputStream fout = new FileOutputStream("test_"+filename);
            fout.write(message);
            fout.close();

        } else{
            message = Arrays.copyOfRange(data,584,data.length);
            if (!crypto.checkHash(message,messageDigest))
                throw new Exception("Integrity or authority violation: Message digest error.");
        }

        return message;
    }

    private void sendBytes(String message) throws IOException{

        byte[] bytes = message.getBytes();

        if (bytes.length>0){
            output.write(bytes);
        }
        output.flush();
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

//    public void sendFile(String filename, String caption) throws IOException{
//
//
//        File file = new File(filename);
//
//        InputStream inputStream = new FileInputStream(file);
//        OutputStream outputStream = clientSocket.getOutputStream();
//
//        byte[] buffer = new byte[BUFFERSIZE];
//        int readBytes;
//
//        while ( (readBytes = inputStream.read(buffer)) > 0){
//
//            outputStream.write(buffer,0,readBytes);
//        }
//
//        outputStream.close();
//        inputStream.close();
//
//
//    }

    public void receievFile() throws Exception{


        CipherInputStream cipherIn = crypto.cipherInput(clientSocket.getInputStream());
        System.out.println(clientSocket.getInputStream());

        byte[] buffer = new byte[256];
        FileOutputStream fileWriter = new FileOutputStream("test.pdf");
        int readBytes;
        System.out.println(cipherIn.available());
        while((readBytes = cipherIn.read(buffer)) > 0){
            System.out.println(readBytes);
            fileWriter.write(buffer,0,readBytes);
        }

        fileWriter.flush();
        fileWriter.close();
    }





}
