import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;

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

                        System.out.println(new String(byteArray));
                    }


                    serverSocket.close();
                    clientSocket.close();

                } catch (IOException e){
                    System.out.println("Client disconnected.");
                }

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

                        encryptMessage(message);
                    }

                } catch (Exception e) {
                    e.printStackTrace();
                }

            }
        });


    }

    /**
     * Method to allow for the receiver and sender threads to run.
     */
    public void start(){

        // Diffie hellman?
        try {
            sendBytes(crypto.getPublicKey().getEncoded());
            crypto.setKUb(receiveBytes());

        } catch (Exception e){
            System.out.println("Failed to send public key.");
            e.printStackTrace();
            System.exit(0);
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
    private void encryptMessage(String message){

        try {
            SecretKey key = crypto.generateSecretKey();
            IvParameterSpec iv = crypto.generateInitialisationVector();

            byte[] encryptedMessage = crypto.encryptWithSecretKey(message, key,iv);
            byte[] encryptedKey = crypto.encryptSecretKey(key);

            ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
            outputStream.write( encryptedKey );
            outputStream.write(iv.getIV());
            outputStream.write( encryptedMessage );

            sendBytes(outputStream.toByteArray());


        } catch (Exception e){
            e.printStackTrace();
        }
    }

    /**
     * Decrypts a byte array that contains an AES session key, an initialisation vector, and some message or data.
     * @param data
     * @return byte array of decrypted message.
     */
    private byte[] decryptMessage(byte[] data){

        byte[] decryptedMessage = {};
        try {

            SecretKey key = crypto.decryptSecretKey(Arrays.copyOfRange(data,0,256));
            IvParameterSpec IV = new IvParameterSpec(Arrays.copyOfRange(data,256,256+16));
            decryptedMessage = crypto.decryptWithSecretKey(Arrays.copyOfRange(data,256+16,data.length),key,IV);
            return decryptedMessage;


        } catch (Exception e){
            e.printStackTrace();
        }

        return decryptedMessage;
    }

    private byte[] receiveBytes() throws IOException {

//        Decryption here

        int length = input.readInt();
        byte[] bytes = new byte[length];

        if (length> 0){
            input.readFully(bytes);
        }

        return bytes;
    }


    /**
     *
     * @param bytes
     * @throws IOException
     */
    private void sendBytes(byte[] bytes) throws IOException{

        // Encryption here on byte array?



        output.writeInt(bytes.length);
        if (bytes.length>0){
            output.write(bytes);
        }

    }


}
