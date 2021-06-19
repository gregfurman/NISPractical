import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
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

public class Server{

    private final Socket clientSocket; // TCP socket of the client.

    private final DataInputStream input; // The input-stream from the client
    private final DataOutputStream output; // The output-stream of the client.
    private final BufferedReader keyboardInput; // BufferedReader that allows for user input from the keyboard.

    private final ServerSocket serverSocket; // TCP socket for server.

    private Cryptography crypto; // Attribute that contains all cryptographic methods.

    public static void main(String[] args){

        try {
            Server server = new Server(6666);

            server.start();

        } catch (IOException e){
            System.out.println("Error in client connecting to server.");
        } catch (NoSuchAlgorithmException a){
            System.out.println("Fatal error: RSA key pairs failed to load/generate.");
        }

    }

    /**
     * Constructor method for the Server class. TCP socket for server is instantiated
     * and blocks until a client connection is made. DataStream attributes are also created
     * for data transmission across scckets.
     * @param portNumber The number of the port in the transport layer in that the server will be connecting to.
     * @throws IOException Exception thrown if the client fails to successfully connect to a socket.
     * @throws NoSuchAlgorithmException Exception thrown if RSA generation fails.
     */
    public Server(int portNumber) throws IOException, NoSuchAlgorithmException {

        crypto = new Cryptography();

        serverSocket = new ServerSocket(portNumber);
        clientSocket = serverSocket.accept();

        output = new DataOutputStream(clientSocket.getOutputStream());
        input = new DataInputStream(clientSocket.getInputStream());

        keyboardInput = new BufferedReader(new InputStreamReader(System.in));

}


    /**
     * Method to create a thread that will constantly be checking for TCP messages from client. An exception is thrown
     * if the client disconnects thus allowing the loop to break and program to terminate.
     * @return Thread that checks for any bytes being received from client.
     */
    private Thread receiverThread(){

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


                    serverSocket.close();
                    clientSocket.close();


                } catch (IOException e){
                    System.out.println("Client disconnected.");
                } catch (Exception e){
                    e.printStackTrace();
                    System.out.println("Fatal error: decryption failed.");
                }
                System.exit(0);

            }
        });

    }

    /**
     * Method to create a thread that will constantly be checking for keyboard input
     * to send via a TCP message to a client. An exception is thrown
     * if keyboard input encounters an error.
     * @return Thread that checks for any bytes being received from client.
     */
    private Thread senderThread(){


        return new Thread(new Runnable() {
            @Override
            public void run() {

                try {
                    String message;
                    // readLine() blocks until some input is encountered.
                    // If a user inputs "quit", the loop terminates.
                    while (!(message = keyboardInput.readLine()).equals("quit")) {

//                        sendBytes(encryptMessage(message));
                        sendBytes(encryptFile("prac.pdf","Test"));
                    }


                } catch (Exception e) {
                    e.printStackTrace();
                }

                System.exit(0);
            }
        });


    }

    /**
     * Method to allow for the receiver and sender threads to run.
     */
    public void start(){

        try {

            //Creates a certificate and sends it to client
            X509Certificate myID = CA.createCertificate("CN=Alice, C=CapeTown, C=ZA", crypto.getPublicKey());
            System.out.println("Sending Bob my certificate (I'm Alice) ");
            sendBytes(myID.getEncoded());

            // Received bytes from client and converts it to a certificate
            byte [] senderCertificate = receiveBytes();
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            ByteArrayInputStream bobCertificate = new ByteArrayInputStream(senderCertificate);
            Certificate certificate = cf.generateCertificate(bobCertificate);
            System.out.println("Received bob's certificate");

            // Retrieves authorities public key and verifies the certificate
            PublicKey AuthorityPubKey = CA.getPublicKey();
            certificate.verify(AuthorityPubKey);
            System.out.println("Verified bob's certificate");

            // Retrieves clients public key from the certificate and saves it.
            crypto.setKUb(certificate.getPublicKey().getEncoded());
            System.out.println("Received bob's public key");
            


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
    private byte[] encryptMessage(String message) throws Exception{

        // Session key component
        ByteArrayOutputStream SessionKeyComponent = new ByteArrayOutputStream();

        byte[] recipientPublicKey = crypto.getReceipientKey().getEncoded();
        System.out.println("Public key object length: "+recipientPublicKey.length);
        SessionKeyComponent.write(recipientPublicKey);

        SecretKey key = crypto.generateSecretKey();
        byte[] encryptedKey = crypto.encryptSecretKey(key);
        SessionKeyComponent.write(encryptedKey);
        System.out.println("Session key length: "+encryptedKey.length);

        // adding init vector - maybe encrypt?
        IvParameterSpec iv = crypto.generateInitialisationVector();
        SessionKeyComponent.write(iv.getIV());
        System.out.println("IV length: "+iv.getIV().length);



        // Signature
        ByteArrayOutputStream Signature = new ByteArrayOutputStream();

        // converting hash of datetime to 32 byte array
        Date today = new Date();
        byte[] timeStamp =  ByteBuffer.allocate(32).putInt(new Date(today.getTime() + 100).hashCode()).array();
        Signature.write(timeStamp);

        byte[] myPublicKey = crypto.getPublicKey().getEncoded();
        Signature.write(myPublicKey);

        byte[] messageDigest = crypto.privateKeyEncrypt(crypto.sha512(message.getBytes()));
        System.out.println("Message digest length: " +messageDigest.length);
        byte[] leadingOctets =  Arrays.copyOfRange(messageDigest,0,2);
        Signature.write(leadingOctets);

        Signature.write(messageDigest);

        // Message
        ByteArrayOutputStream Message = new ByteArrayOutputStream();
        Message.write(message.getBytes());
        //filename
        //file size
        // file data
        // add in file !
        // caption jazz as well !

        // Adding message byte array to end of signature for compression
        Signature.write(Message.toByteArray());

        byte[] compressedAndEncryptedMessage = crypto.encryptWithSecretKey(compress(Signature.toByteArray()), key,iv); // Here is where compression takes place.

        ByteArrayOutputStream PGPMessage = new ByteArrayOutputStream( );
        PGPMessage.write(SessionKeyComponent.toByteArray());
        PGPMessage.write(compressedAndEncryptedMessage);


        return Base64.getEncoder().encode(PGPMessage.toByteArray());

    }


    /**
     * Method to encrypt a string message using AES ecnryption with an ephemeral session key and
     * initialisation vector. The resulting message, key, and IV are sent as bytes to the client.
     * @param caption String message to encrypted and sent to client.
     * @param filename String filename of file to be sent.
     */
    private byte[] encryptFile(String filename, String caption) throws Exception{

        // Session key component
        ByteArrayOutputStream SessionKeyComponent = new ByteArrayOutputStream();

        byte[] recipientPublicKey = crypto.getReceipientKey().getEncoded();
        System.out.println("Public key object length: "+recipientPublicKey.length);
        SessionKeyComponent.write(recipientPublicKey);

        SecretKey key = crypto.generateSecretKey();
        byte[] encryptedKey = crypto.encryptSecretKey(key);
        SessionKeyComponent.write(encryptedKey);
        System.out.println("Session key length: "+encryptedKey.length);

        // adding init vector - maybe encrypt?
        IvParameterSpec iv = crypto.generateInitialisationVector();
        SessionKeyComponent.write(iv.getIV());
        System.out.println("IV length: "+iv.getIV().length);



        // Signature
        ByteArrayOutputStream Signature = new ByteArrayOutputStream();

        // converting hash of datetime to 32 byte array
        Date today = new Date();
        byte[] timeStamp =  ByteBuffer.allocate(32).putInt(new Date(today.getTime() + 100).hashCode()).array();
        Signature.write(timeStamp);

        byte[] myPublicKey = crypto.getPublicKey().getEncoded();
        Signature.write(myPublicKey);


        File file = new File(filename);

        if (!file.exists())
            throw new Exception("Error: file does not exist.");

        byte[] FileAsBytes = Files.readAllBytes(file.toPath());

        byte[] messageDigest = crypto.privateKeyEncrypt(crypto.sha512(FileAsBytes));
        System.out.println("Message digest length: " +messageDigest.length);
        byte[] leadingOctets =  Arrays.copyOfRange(messageDigest,0,2);
        Signature.write(leadingOctets);

        Signature.write(messageDigest);

        byte[] captionBytes = caption.getBytes();
        byte[] filenameBytes = filename.getBytes();
        // Message
        ByteArrayOutputStream Message = new ByteArrayOutputStream();

        // byte array of 1 indicating file
        Message.write(new byte[]{1});
        Message.write(ByteBuffer.allocate(4).putInt(captionBytes.length).array());
        Message.write(captionBytes);


        // Filename
        Message.write(ByteBuffer.allocate(4).putInt(filenameBytes.length).array());
        Message.write(filenameBytes);

        // Read in length of file
        Message.write(ByteBuffer.allocate(8).putLong(file.length()).array());
        Message.write(FileAsBytes);

        // Adding message byte array to end of signature for compression
        Signature.write(Message.toByteArray());

        byte[] compressedAndEncryptedMessage = crypto.encryptWithSecretKey(compress(Signature.toByteArray()), key,iv); // Here is where compression takes place.

        ByteArrayOutputStream PGPMessage = new ByteArrayOutputStream( );
        PGPMessage.write(SessionKeyComponent.toByteArray());
        PGPMessage.write(compressedAndEncryptedMessage);


        return Base64.getEncoder().encode(PGPMessage.toByteArray());

    }


    /**
     * Decrypts a byte array that contains an AES session key, an initialisation vector, and some message or data.
     * @param rawMessageData
     * @return byte array of decrypted message.
     */
    private byte[] decryptMessage(byte[] rawMessageData) throws Exception{

        byte[] decodedData = Base64.getDecoder().decode(rawMessageData);
        // Length of byte array of public key object in java is 294 bytes. Go figure.
        byte[] publicKey = Arrays.copyOfRange(decodedData,0,294);

        if (!crypto.isPublicKey(publicKey))
            throw new Exception("Destination ID is incorrect.");

        SecretKey key = crypto.decryptSecretKey(Arrays.copyOfRange(decodedData,294,550));
        IvParameterSpec iv = new IvParameterSpec(Arrays.copyOfRange(decodedData,550,566)); // Maybe decrypt?

        // Decrypt signature!

        byte[] data = decompress(crypto.decryptWithSecretKey(Arrays.copyOfRange(decodedData,566,decodedData.length),key,iv));

        Date timestamp = new Date(new BigInteger(Arrays.copyOfRange(data,0,32)).intValue());
        Date now = new Date();
        long SecondsToArrive= ((now.getTime()- timestamp.getTime() )/1000)%60;

        // TTL
        if (SecondsToArrive > 60)
            throw new Exception(String.format("Time to live of message has expired: took %d seconds.",SecondsToArrive));


        byte[] senderPublicKey = Arrays.copyOfRange(data,32,326);
        if (!crypto.isSendersPublicKey(senderPublicKey))
            throw new Exception("Sender ID is incorrect.");

        byte[] octets = Arrays.copyOfRange(data,326,328); // ???

        byte[] messageDigest = crypto.PublicKeyDecryptB(Arrays.copyOfRange(data,328,584));

        // Message Decrypt!

        byte[] message = Arrays.copyOfRange(data,584,data.length);

        if (!crypto.checkHash(message,messageDigest))
            throw new Exception("Integrity or authority violation: Message digest error.");

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

        bos.flush();

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
