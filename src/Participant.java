import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.zip.*;

public class Participant{

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
            // The wrapped stream does not close when method is called.
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

    private final Socket clientSocket; // TCP socket of the client.

    private final DataInputStream input; // The input-stream from the client
    private final DataOutputStream output; // The output-stream to the client.
    private final BufferedReader keyboardInput; // BufferedReader that allows for user input from the keyboard.

    private ServerSocket serverSocket; // TCP socket for server.

    private Cryptography crypto; // Attribute that contains all cryptographic methods.

    private String name,other;

    final String HOME_DIRECTORY;

    private final String ALICE = "Alice";
    private final String BOB = "Bob";

    public static final String ANSI_YELLOW = "\u001B[33m";
    public static final String ANSI_RESET = "\u001B[0m";
    public static final String ANSI_GREEN = "\u001B[32m";
    public static final String ANSI_BLUE = "\u001B[34m";
    public static final String ANSI_PURPLE = "\u001B[35m";
    public static final String ITALIC = "\033[3m";
    public static final String NORMAL = "\033[0m";


    /**
     * Constructor method for the Participant class when Participant is the Server. TCP socket for server is instantiated
     * and blocks until a participant connection is made. DataStream attributes are also created
     * for data transmission across sockets.
     * @param portNumber The number of the port in the transport layer in that the server will be connecting to.
     * @throws IOException Exception thrown if the participant fails to successfully connect to a socket.
     * @throws NoSuchAlgorithmException Exception thrown if RSA generation fails.
     */
    public Participant(int portNumber) throws IOException, NoSuchAlgorithmException {

        HOME_DIRECTORY = "SERVER_HOME";
        name = ALICE;
        other = BOB;
        crypto = new Cryptography();

        serverSocket = new ServerSocket(portNumber);
        clientSocket = serverSocket.accept();

        output = new DataOutputStream(clientSocket.getOutputStream());
        input = new DataInputStream(clientSocket.getInputStream());

        keyboardInput = new BufferedReader(new InputStreamReader(System.in));

    }

    /**
     * Constructor method for the Participant class when Participant is Client. TCP socket for participant is set by
     * connecting to a server socket. DataStream attributes are also created
     * for data transmission across sockets.
     * @param portNumber The number of the port in the transport layer in that the server will be connecting to.
     * @throws IOException Exception thrown if the participant fails to successfully connect to a socket.
     * @throws NoSuchAlgorithmException Exception thrown if RSA generation fails.
     */
    public Participant(String address,int portNumber) throws IOException, NoSuchAlgorithmException {

        HOME_DIRECTORY = "CLIENT_HOME";

        name = BOB;
        other = ALICE;

        crypto = new Cryptography();
        clientSocket = new Socket(address, portNumber);

        output = new DataOutputStream(clientSocket.getOutputStream());
        input = new DataInputStream(clientSocket.getInputStream());

        keyboardInput = new BufferedReader(new InputStreamReader(System.in));

    }


    /**
     * Method to create a thread that will constantly be checking for TCP messages from participant. An exception is thrown
     * if the participant disconnects thus allowing the loop to break and program to terminate.
     * @return Thread that checks for any bytes being received from participant.
     */
    private Thread receiverThread(){

        return new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    byte[] byteArray;
                    // While loop that blocks on the receiveByres method.
                    while ((byteArray = receiveBytes()) != null) {

                        System.out.println(ANSI_GREEN + other+": " + receiveInput(byteArray));
                        System.out.print(ANSI_BLUE+"Me: "+ANSI_RESET);

                    }

                    if (serverSocket != null)
                        serverSocket.close();

                    clientSocket.close();


                } catch (Exception e){
                    System.out.println("Participant disconnected.");
                }
                System.exit(0);

            }
        });

    }

    /**
     * Method to create a thread that will constantly be checking for keyboard input
     * to send via a TCP message to a participant. An exception is thrown
     * if keyboard input encounters an error.
     * @return Thread that checks for any bytes being received from participant.
     */
    private Thread senderThread(){


        return new Thread(new Runnable() {
            @Override
            public void run() {

                try {
                    String message;

                    // readLine() blocks until some input is encountered.
                    // If a user inputs "quit", the loop terminates.

                    System.out.println(ANSI_PURPLE+"Welcome\nSend a message or type '-file' to send a file"+ANSI_RESET);
                    System.out.print(ANSI_BLUE+"Me: "+ANSI_RESET);

                    while (!(message = keyboardInput.readLine()).equals("-quit")) {
                        if (message.equals("-file")) {
                            System.out.println(ANSI_BLUE+"Enter filename:");
                            String fileName = keyboardInput.readLine();
                            System.out.println("Enter caption:"+ANSI_RESET);
                            String caption = keyboardInput.readLine();
                            sendFile(fileName, caption);
                        } else if(message.equals("-quit")) {
                            break;
                        }
                        else{
                            sendMessage(message);
                        }
                        System.out.print(ANSI_BLUE+"Me: "+ANSI_RESET);
                    }

                } catch (Exception e) {
                    System.out.println(NORMAL);
                    System.out.println("An error occurred: disconnecting.");
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

            //Creates a certificate and sends it to participant
            X509Certificate myID = CertificateAuthority.createCertificate("CN="+other+", C=CapeTown, C=ZA", crypto.getPublicKey());
            System.out.println(ANSI_YELLOW + ITALIC + "Sending "+other+" my certificate (I'm "+name+ ") " + ANSI_RESET);

            sendBytes(myID.getEncoded());

            // Received bytes from participant and converts it to a certificate
            byte [] senderCertificate = receiveBytes();
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            ByteArrayInputStream aliceCertificate = new ByteArrayInputStream(senderCertificate);
            Certificate certificate = cf.generateCertificate(aliceCertificate);
            System.out.println(ANSI_YELLOW + ITALIC + "Received " + other + "'s certificate");

            // Retrieves authorities public key and verifies the certificate
            PublicKey AuthorityPubKey = CertificateAuthority.getPublicKey();
            certificate.verify(AuthorityPubKey);
            System.out.println(ANSI_YELLOW + ITALIC + "Verified " + other+ "'s certificate");

            // Retrieves participant public key from the certificate and saves it.
            crypto.setKUb(certificate.getPublicKey().getEncoded());
            System.out.println(ANSI_YELLOW + ITALIC + "Received " +other+ "'s public key" + ANSI_RESET);



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
     * Method to encrypt a string message using AES encryption with an ephemeral session key and
     * initialisation vector. The resulting message, key, and IV are sent as bytes to the participant.
     * @param caption String message to encrypted and sent to participant.
     * @param filename String filename of file to be sent.
     */
    private void sendFile(String filename, String caption) throws Exception{

        File file = new File(HOME_DIRECTORY + "/"+filename);
        if (!file.exists()) {
            System.out.println(filename + " cannot be found.");
            return;
        }

        ByteArrayOutputStream SessionKeyComponent = new ByteArrayOutputStream();

        byte[] recipientPublicKey = crypto.getReceipientKey().getEncoded();
        SessionKeyComponent.write(recipientPublicKey);

        SecretKey key = crypto.generateSecretKey();
        byte[] encryptedKey = crypto.encryptSecretKey(key);
        SessionKeyComponent.write(encryptedKey);

        // adding init vector - maybe encrypt?
        IvParameterSpec iv = crypto.generateInitialisationVector();
        SessionKeyComponent.write(iv.getIV());


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
        byte[] fileLength = ByteBuffer.allocate(8).putLong(file.length()).array();
        Message.write(fileLength);

        ByteArrayOutputStream concat = new ByteArrayOutputStream();
        concat.write(SessionKeyComponent.toByteArray());
        concat.write(crypto.encryptWithSecretKey(compress(Message.toByteArray()),key,iv));
        sendBytes(Base64.getEncoder().encode(concat.toByteArray()));

        md.update(Message.toByteArray());
        Message.close();

        Message.close();


        try{

            FileInputStream fis = new FileInputStream(HOME_DIRECTORY +"/"+ filename);
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

        // converting hash of datetime to 8 byte array
        Date today = new Date();
        byte[] timeStamp =  ByteBuffer.allocate(8).putLong(today.getTime()).array();
        Signature.write(timeStamp);

        byte[] myPublicKey = crypto.getPublicKey().getEncoded();
        Signature.write(myPublicKey);
        Signature.write(crypto.privateKeyEncrypt(md.digest()));

        sendBytes(Base64.getEncoder().encode(crypto.encryptWithSecretKey(compress(Signature.toByteArray()),key,iv)));

        Signature.close();

    }

    /**
     * Decrypts a byte array that contains an AES session key, an initialisation vector, and some message or data.
     * @param rawMessageData
     * @return byte array of decrypted message.
     */
    private String receiveInput(byte[] rawMessageData) throws Exception{

        byte[] decodedData = Base64.getDecoder().decode(rawMessageData);

        // Length of byte array of public key object in java is 294 bytes. Go figure.

        // Session component
        byte[] publicKey = Arrays.copyOfRange(decodedData,0,294);

        if (!crypto.isPublicKey(publicKey))
            throw new Exception("Destination ID is incorrect.");

        SecretKey key = crypto.decryptSecretKey(Arrays.copyOfRange(decodedData,294,550));
        IvParameterSpec iv = crypto.decodeInitialisationVector(Arrays.copyOfRange(decodedData,550,566)); // Maybe decrypt?

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key,iv);


        // Message
        byte[] Message = decompress(crypto.decryptWithSecretKey(Arrays.copyOfRange(decodedData,566,decodedData.length),key,iv));

        int bytesRead = 0;

        boolean isFile =  Message[bytesRead] == 1;
        bytesRead += 1;

        byte[] message=null;
        MessageDigest md = MessageDigest.getInstance(crypto.MESSAGE_DIGEST_ALGORITHM);

        if (isFile) {
            // Length of caption string in byte form to allow for reading from data
            int captionLength = new BigInteger(Arrays.copyOfRange(Message,bytesRead,bytesRead+4)).intValue();
            bytesRead+=4;
            message = Arrays.copyOfRange(Message,bytesRead,captionLength+bytesRead);
            System.out.println(ITALIC + "Decrypted caption: " + ANSI_PURPLE +new String(message, "UTF-8") +ANSI_RESET);

            bytesRead+=captionLength;

            // Length of filename string in byte form to allow for reading from data
            int fileNameLength = new BigInteger(Arrays.copyOfRange(Message,bytesRead,bytesRead+4)).intValue();
            bytesRead+=4;

            String filename =  new String(Arrays.copyOfRange(Message,bytesRead,bytesRead+fileNameLength), "UTF-8");
            System.out.println(ITALIC+ "Decrypted filename: "+ ANSI_PURPLE+ filename +ANSI_RESET);
            bytesRead+=fileNameLength;

            // Length of file used to read bytes that correspond to file
            long fileLength =  ByteBuffer.wrap(Arrays.copyOfRange(Message,bytesRead,bytesRead+8)).getLong();
            bytesRead+=8;


            md.update(Arrays.copyOfRange(Message,0,bytesRead));

            try( FileOutputStream fout = new FileOutputStream(HOME_DIRECTORY+ "/" +filename);){

                Inflater inflater = new Inflater(true);
                InflaterInputStream inf = new InflaterInputStream(input,inflater);
                CipherInputStream Cin = new CipherInputStream(inf,cipher);

                byte[] buffer = new byte[512];
                int count;
                long readBytes = 0;
                while ((count = Cin.read(buffer)) >0){

                    fout.write(buffer, 0, count);
                    md.update(buffer,0,count);
                    readBytes += count;
                }

                if (fileLength != readBytes){
                    throw new Exception();
                }

            }catch (Exception e){
                System.out.println("Failed to receive file.");
            }


        } else{

            // Gets length of message (in bytes)
            int messageLength =new BigInteger(Arrays.copyOfRange(Message,bytesRead,bytesRead+4)).intValue();
            bytesRead +=4;

            // Loads the actual message (in bytes)
            message = Arrays.copyOfRange(Message,bytesRead,messageLength+bytesRead);
            bytesRead+= messageLength;

            // Updates the message digest from index 0 to the amount of bytes read
            md.update(Arrays.copyOfRange(Message,0,bytesRead));

        }

        // Signature
        byte[] Signature = decompress(crypto.decryptWithSecretKey(Base64.getDecoder().decode(receiveBytes()),key,iv));

        bytesRead = 0;

        Date timestamp = new Date(ByteBuffer.wrap(Arrays.copyOfRange(Signature,bytesRead,bytesRead+8)).getLong());
        bytesRead+= 8;
        Date now = new Date();
        long SecondsToArrive= ((now.getTime()- timestamp.getTime() )/1000)%60;

        System.out.println("Message took: " +  (now.getTime() - timestamp.getTime()) + "ms to transfer." );

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
     * initialisation vector. The resulting message, key, and IV are sent as bytes to the participant.
     * @param message String message to encrypted and sent to participant.
     */
    private void sendMessage(String message) throws Exception{

        ByteArrayOutputStream SessionKeyComponent = new ByteArrayOutputStream();

        byte[] recipientPublicKey = crypto.getReceipientKey().getEncoded();

        SessionKeyComponent.write(recipientPublicKey);

        SecretKey key = crypto.generateSecretKey();
        byte[] encryptedKey = crypto.encryptSecretKey(key);
        SessionKeyComponent.write(encryptedKey);


        // adding init vector - maybe encrypt?
        IvParameterSpec iv = crypto.generateInitialisationVector();
        SessionKeyComponent.write(iv.getIV());

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

        Message.close();

        // for synch. purposes
        Thread.sleep(500);
        // Signature
        ByteArrayOutputStream Signature = new ByteArrayOutputStream();

        // converting hash of datetime to 8 byte array
        Date today = new Date();
        byte[] timeStamp =  ByteBuffer.allocate(8).putLong(today.getTime()).array();
        Signature.write(timeStamp);

        byte[] myPublicKey = crypto.getPublicKey().getEncoded();
        Signature.write(myPublicKey);
        Signature.write(crypto.privateKeyEncrypt(md.digest()));

        sendBytes(Base64.getEncoder().encode(crypto.encryptWithSecretKey(compress(Signature.toByteArray()),key,iv)));

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

        bos.flush();

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
