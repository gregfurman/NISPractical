import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.zip.*;


public class Client {


    public class UnclosingOutputStream extends OutputStream {
        /**
         * Wrapper for output stream that does not close the stream when .close() is called.
         * Useful for when CipherOutputStream is used and the cascading .close() required to write all
         * bytes does not close the output stream from socket A to socket B.
         */

        private final OutputStream os;

        public UnclosingOutputStream(OutputStream os) {
            this.os = os;
        }

        @Override
        public void write(int b) throws IOException {
            os.write(b);
        }

        @Override
        public void close() throws IOException {
            // not closing the stream.
        }

        @Override
        public void flush() throws IOException {
            os.flush();
        }

        @Override
        public void write(byte[] buffer, int offset, int count) throws IOException {
            os.write(buffer, offset, count);
        }

        @Override
        public void write(byte[] buffer) throws IOException {
            os.write(buffer);
        }
    }

    private final Socket clientSocket; // TCP socket of client.

    private final DataInputStream input; // The input-stream from the server
    private final DataOutputStream output; // The output-stream to the server.
    private final BufferedReader keyboardInput; // BufferedReader that allows for user input from the keyboard.

    private Cryptography crypto; // Attribute that contains all cryptographic methods.

    /**
     * Main method of program. When run, the client socket will attempt to connect to a server
     * at a given IP and port number.
     * @param args Arguments to the program.
     */
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

    /**
     * Constructor method for the Client class. TCP socket for client is set by
     * connecting to a server socket. DataStream attributes are also created
     * for data transmission across sockets.
     * @param portNumber The number of the port in the transport layer in that the server will be connecting to.
     * @throws IOException Exception thrown if the client fails to successfully connect to a socket.
     * @throws NoSuchAlgorithmException Exception thrown if RSA generation fails.
     */
    public Client(String address,int portNumber) throws IOException, NoSuchAlgorithmException {

        crypto = new Cryptography();
        clientSocket = new Socket(address, portNumber);

        output = new DataOutputStream(clientSocket.getOutputStream());
        input = new DataInputStream(clientSocket.getInputStream());

        keyboardInput = new BufferedReader(new InputStreamReader(System.in));

    }


    /**
     * Method to create a thread that will constantly be checking for TCP messages from client. An exception is thrown
     * if the client disconnects thus allowing the loop to break and program to terminate.
     * @return Thread that checks for any bytes being received from client.
     */
    private Thread receiverThread() {

        return new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    byte[] byteArray;
                    // While loop that blocks on the receiveByres method.
                    while ((byteArray = receiveBytes()) != null) {

                        // Decryption!!
                        System.out.println(recieveInput(byteArray));
//                        System.out.println(new String(decryptMessage(byteArray)));

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

                    while (!(message = keyboardInput.readLine()).equals("quit")) {

                        sendFile("prac.pdf",message);

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
            X509Certificate myID = CertificateAuthority.createCertificate("CN=BOB, C=CapeTown, C=ZA", crypto.getPublicKey());
            System.out.println("Sending Alice my certificate (I'm Bob) ");
            sendBytes(myID.getEncoded());

            // Received bytes from server and converts it to a certificate
            byte [] senderCertificate = receiveBytes();
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            ByteArrayInputStream aliceCertificate = new ByteArrayInputStream(senderCertificate);
            Certificate certificate = cf.generateCertificate(aliceCertificate);
            System.out.println("Received alice's certificate");

            // Retrieves authorities public key and verifies the certificate
            PublicKey AuthorityPubKey = CertificateAuthority.getPublicKey();
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
     * Decrypts a byte array that contains an AES session key, an initialisation vector, and some message or data.
     * @param rawMessageData
     * @return byte array of decrypted message.
     */
    private String recieveInput(byte[] rawMessageData) throws Exception{

        byte[] decodedData = Base64.getDecoder().decode(rawMessageData);

        // Length of byte array of public key object in java is 294 bytes. Go figure.

        // Session component
        byte[] publicKey = Arrays.copyOfRange(decodedData,0,294);

        if (!crypto.isPublicKey(publicKey))
            throw new Exception("Destination ID is incorrect.");

        SecretKey key = crypto.decryptSecretKey(Arrays.copyOfRange(decodedData,294,550));
        System.out.println("Received Secret Key.");
        IvParameterSpec iv = new IvParameterSpec(Arrays.copyOfRange(decodedData,550,566)); // Maybe decrypt?
        System.out.println("Received init. vector.");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key,iv);


        // Message
        byte[] Message = decompress(crypto.decryptWithSecretKey(Arrays.copyOfRange(decodedData,566,decodedData.length),key,iv));
        System.out.println("Message headers length of " + Message.length);

        int bytesRead = 0;

        boolean isFile =  Message[bytesRead] == 1;
        bytesRead += 1;

        byte[] message=null;
        MessageDigest md = MessageDigest.getInstance(crypto.MESSAGE_DIGEST_ALGORITHM);

        if (isFile) {
            System.out.println("Message reading...");
            // Length of caption string in byte form to allow for reading from data
            int captionLength = new BigInteger(Arrays.copyOfRange(Message,bytesRead,bytesRead+4)).intValue();
            bytesRead+=4;
            System.out.println("Caption length = " + captionLength);
            message = Arrays.copyOfRange(Message,bytesRead,captionLength+bytesRead);
            System.out.println("Caption: " + new String(message, "UTF-8"));

            bytesRead+=captionLength;

            // Length of filename string in byte form to allow for reading from data
            int fileNameLength = new BigInteger(Arrays.copyOfRange(Message,bytesRead,bytesRead+4)).intValue();
            bytesRead+=4;
            System.out.println("Length of filename: " + fileNameLength);

            String filename =  new String(Arrays.copyOfRange(Message,bytesRead,bytesRead+fileNameLength), "UTF-8");
            System.out.println("Filename: " + filename);
            bytesRead+=fileNameLength;

            // Length of file used to read bytes that correspond to file
            long fileLength =  ByteBuffer.wrap(Arrays.copyOfRange(Message,bytesRead,bytesRead+8)).getLong();
            bytesRead+=8;
            System.out.println("File size: " + fileLength);

            md.update(Arrays.copyOfRange(Message,0,bytesRead));

            try( FileOutputStream fout = new FileOutputStream("test_" +filename);){

                Inflater inflater = new Inflater(true);
                InflaterInputStream inf = new InflaterInputStream(input,inflater);
                CipherInputStream Cin = new CipherInputStream(inf,cipher);

                byte[] buffer = new byte[512];
                int count;
                while ((count = Cin.read(buffer)) >0){

                    fout.write(buffer, 0, count);
                    md.update(buffer,0,count);

                }


            }catch (Exception e){
                e.printStackTrace();
            }


        } else{

            message = Message;
        }

        // Signature
        byte[] Signature = decompress(crypto.decryptWithSecretKey(Base64.getDecoder().decode(receiveBytes()),key,iv));
        System.out.println("Length of signature = " + Signature.length);
        bytesRead = 0;

        Date timestamp = new Date(new BigInteger(Arrays.copyOfRange(Signature,bytesRead, bytesRead+4)).intValue());
        bytesRead+= 4;
        Date now = new Date();
        long SecondsToArrive= ((now.getTime()- timestamp.getTime() )/1000)%60;
        System.out.println(now.toString() + " " + timestamp.toString());

        // If takes longer than 60 seconds timeout
        if (SecondsToArrive > 60)
            throw new Exception(String.format("Time to live of message has expired: took %d seconds.",SecondsToArrive));


        // Get public key of sender
        byte[] senderPublicKey = Arrays.copyOfRange(Signature,bytesRead,bytesRead + 294);
        if (!crypto.isSendersPublicKey(senderPublicKey))
            throw new Exception("Sender ID is incorrect.");
        bytesRead+=294; // length of public key object encoding

        byte[] messageDigest = crypto.PublicKeyDecryptB(Arrays.copyOfRange(Signature,bytesRead,Signature.length));

        // Entire message
        if (!crypto.checkHash(md.digest(),messageDigest))
            throw new Exception("Integrity or authority violation: Message digest error.");

        return new String(message, "UTF-8");

    }


    /**
     * Method to encrypt a string message using AES ecnryption with an ephemeral session key and
     * initialisation vector. The resulting message, key, and IV are sent as bytes to the client.
     * @param caption String message to encrypted and sent to client.
     * @param filename String filename of file to be sent.
     */
    private void sendFile(String filename, String caption) throws Exception{

        File file = new File(filename);
        if (!file.exists())
            throw new FileNotFoundException("File does not exist");

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

        System.out.println("Session component sent: length of " + SessionKeyComponent.toByteArray().length);
        SessionKeyComponent.close();

        Cipher cipher = Cipher.getInstance(crypto.SECRET_KEY_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key,iv);

        MessageDigest md = MessageDigest.getInstance(crypto.MESSAGE_DIGEST_ALGORITHM);

        ByteArrayOutputStream Message = new ByteArrayOutputStream();

        // 1 indicating file

        Message.write(new byte[]{1});


        // File caption length
        byte[] captionBytes = caption.getBytes();
        byte[] captionLength = ByteBuffer.allocate(4).putInt(captionBytes.length).array();
        Message.write(captionLength);
        Message.write(captionBytes);

        // Filename
        byte[] filenameBytes = filename.getBytes();
        byte[] filenameLength = ByteBuffer.allocate(4).putInt(filenameBytes.length).array();

        Message.write(filenameLength);
        Message.write(filenameBytes);

        // File length
        System.out.println("File size: " + file.length());
        byte[] fileLength = ByteBuffer.allocate(8).putLong(file.length()).array();
        Message.write(fileLength);

        ByteArrayOutputStream concat = new ByteArrayOutputStream();
        concat.write(SessionKeyComponent.toByteArray());
        concat.write(crypto.encryptWithSecretKey(compress(Message.toByteArray()),key,iv));
        sendBytes(Base64.getEncoder().encode(concat.toByteArray()));

        md.update(Message.toByteArray());
        Message.close();

        System.out.println("Sending message headers: length of " + crypto.encryptWithSecretKey(compress(Message.toByteArray()),key,iv).length);

        Message.close();

        try{

            FileInputStream fis = new FileInputStream(filename);
            UnclosingOutputStream nos = new UnclosingOutputStream(output);
            Deflater deflater = new Deflater(Deflater.BEST_COMPRESSION,true);
            DeflaterOutputStream dos = new DeflaterOutputStream(nos,deflater,true);
            CipherOutputStream CZout = new CipherOutputStream(dos,cipher);

            byte[] buffer = new byte[512];
            int count;
            while ((count = fis.read(buffer))>0){

                CZout.write(buffer,0,count);
                md.update(buffer,0,count);

            }

            fis.close();
            CZout.close();

        } catch (IOException e){
            e.printStackTrace();
        }

        // for synch. purposes
        Thread.sleep(500);
        // Signature
        ByteArrayOutputStream Signature = new ByteArrayOutputStream();

        // converting hash of datetime to 32 byte array
        Date today = new Date();
        byte[] timeStamp =  ByteBuffer.allocate(4).putInt(new Date(today.getTime()).hashCode()).array();
        Signature.write(timeStamp);
        System.out.println("MD length: " + md.getDigestLength());

        byte[] myPublicKey = crypto.getPublicKey().getEncoded();
        Signature.write(myPublicKey);
        Signature.write(crypto.privateKeyEncrypt(md.digest()));

        sendBytes(Base64.getEncoder().encode(crypto.encryptWithSecretKey(compress(Signature.toByteArray()),key,iv)));


        System.out.println("Sending Signature: length of " + Signature.toByteArray().length);


        Signature.close();


    }

    /**
     * Method to encrypt a string message using AES ecnryption with an ephemeral session key and
     * initialisation vector. The resulting message, key, and IV are sent as bytes to the client.
     * @param message String message to encrypted and sent to client.
     */
    private void sendMessage(String message) throws Exception{

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

        System.out.println("Session component sent: length of " + SessionKeyComponent.toByteArray().length);
        SessionKeyComponent.close();

        Cipher cipher = Cipher.getInstance(crypto.SECRET_KEY_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key,iv);

        MessageDigest md = MessageDigest.getInstance(crypto.MESSAGE_DIGEST_ALGORITHM);

        ByteArrayOutputStream Message = new ByteArrayOutputStream();

        // 1 indicating message
        Message.write(new byte[]{0});

        // File caption length
        byte[] messageBytes = message.getBytes();
        byte[] messageLength = ByteBuffer.allocate(4).putInt(messageBytes.length).array();
        Message.write(messageLength);
        Message.write(messageBytes);

        ByteArrayOutputStream concat = new ByteArrayOutputStream();
        concat.write(SessionKeyComponent.toByteArray());
        concat.write(crypto.encryptWithSecretKey(compress(Message.toByteArray()),key,iv));
        sendBytes(Base64.getEncoder().encode(concat.toByteArray()));

        md.update(Message.toByteArray());
        Message.close();

        System.out.println("Sending message headers: length of " + crypto.encryptWithSecretKey(compress(Message.toByteArray()),key,iv).length);

        Message.close();

        // for synch. purposes
        Thread.sleep(500);
        // Signature
        ByteArrayOutputStream Signature = new ByteArrayOutputStream();

        // converting hash of datetime to 32 byte array
        Date today = new Date();
        byte[] timeStamp =  ByteBuffer.allocate(4).putInt(new Date(today.getTime()).hashCode()).array();
        Signature.write(timeStamp);
        System.out.println("MD length: " + md.getDigestLength());

        byte[] myPublicKey = crypto.getPublicKey().getEncoded();
        Signature.write(myPublicKey);
        Signature.write(crypto.privateKeyEncrypt(md.digest()));
        System.out.println(Arrays.toString(md.digest()));

        sendBytes(Base64.getEncoder().encode(crypto.encryptWithSecretKey(compress(Signature.toByteArray()),key,iv)));


        System.out.println("Sending Signature: length of " + Signature.toByteArray().length);

        Signature.close();


    }

    /**
     * Compresses a byte array using and produces zlib-wrapped deflate compressed data.
     * @param data Uncompressed data to be compressed.
     * @return Byte array of compressed (or deflated) data.
     * @throws IOException Thrown if I/O exception occurs when creating compressed data.
     */
    private byte[] compress(byte[] data) throws IOException{

        ByteArrayOutputStream bos = new ByteArrayOutputStream();

        Deflater deflater = new Deflater(Deflater.BEST_COMPRESSION,true);

        DeflaterOutputStream dos = new DeflaterOutputStream(bos,deflater);

        dos.write(data);

        dos.close();

        return bos.toByteArray();

    }

    /**
     * Decompressed zlib-wrapped deflate compressed data and produces a byte array.
     * @param data Byte array of compressed data.
     * @return Byte array of uncompressed (or inflated) data.
     * @throws IOException Thrown if I/O exception occurs when decompressing data.
     */
    private byte[] decompress(byte[] data) throws IOException{


        ByteArrayOutputStream bos = new ByteArrayOutputStream();

        Inflater inflater = new Inflater(true);

        InflaterOutputStream ios = new InflaterOutputStream(bos,inflater);

        ios.write(data);
        ios.close();

        return bos.toByteArray();

    }

    /**
     * Function for receiving bytes from socket.
     * @return Byte array of received bytes.
     * @throws IOException Thrown if I/O error occurs when reading byte data from input stream.
     */
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
     * Function for sending bytes via output stream to socket.
     * @param data Data to be sent.
     * @throws IOException Thrown if I/O error occurs when writing data to stream.
     */
    private void sendBytes(byte[] data) throws IOException{

        if (data.length>0){
            output.write(data);
        }
        output.flush();
    }

}
