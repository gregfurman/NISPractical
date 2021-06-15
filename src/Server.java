import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;

public class Server{


    private static int BUFFERSIZE = 2048;

    private final Socket clientSocket;

    private final DataInputStream input;
    private final DataOutputStream output;
    private final BufferedReader keyboardInput;

    private final ServerSocket serverSocket;

    private Cryptography crypto;

    public static void main(String[] args){

        try {
            Server server = new Server(6666);

            server.start();

        } catch (IOException e){
            System.out.println("Error in client connecting to server.");
        }

    }

    public Server(int portNumber) throws IOException {

        try {
            crypto = new Cryptography();
        } catch (NoSuchAlgorithmException a){
            System.out.println("Fatal error: RSA-key generation failed.");
            System.exit(1);
        }

        serverSocket = new ServerSocket(portNumber);
        clientSocket = serverSocket.accept();

        output = new DataOutputStream(clientSocket.getOutputStream());
        input = new DataInputStream(clientSocket.getInputStream());

        keyboardInput = new BufferedReader(new InputStreamReader(System.in));

}



    private Thread receiverThread(){

        return new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    byte[] byteArray;
                    while ((byteArray = recieveBytes()) != null) {
                        // Decryption!!

                        System.out.println(new String(byteArray));
                    }


                    serverSocket.close();
                    clientSocket.close();

                } catch (IOException e){
                    System.out.println("Client disconnected.");
                    System.exit(0);
                }

            }
        });

    }

    // Place threads in own class?
    private Thread senderThread(){

        return new Thread(new Runnable() {
            @Override
            public void run() {

                try {
                    String message;

                    while (!(message = keyboardInput.readLine()).equals("quit")) {
                        // Encrpytion!!

//                        encryptMessage(message);
                        sendBytes(message);



                    }

                } catch (Exception e) {
                    e.printStackTrace();
                }

            }
        });


    }

    public void start(){

        // Diffie hellman?
        try {
            sendBytes(crypto.getPublicKey().getEncoded());
            crypto.setKUb(recieveBytes());

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


    private void encryptMessage(String message){

        try {
            SecretKey key = crypto.generateSecretKey();

            byte[] encryptedMessage = crypto.encryptWithSecretKey(message, key);
            byte[] encryptedKey = crypto.encryptSecretKey(key);

//            System.out.println(encryptedMessage.length);
//            System.out.println(encryptedKey.length);
//            sendBytes();

        } catch (Exception e){
            e.printStackTrace();
        }
    }

    private byte[] recieveBytes() throws IOException {

//        Decryption here

        int length = input.readInt();
        byte[] bytes = new byte[length];

        if (length> 0){
            input.readFully(bytes);
        }

        return bytes;
    }


    private void sendMessage(String message) throws IOException{
        sendBytes(message.getBytes(StandardCharsets.UTF_8));
    }


    private void sendBytes(String message) throws IOException{

        // Encryption here on byte array?
        byte[] bytes = message.getBytes();

        output.writeInt(bytes.length);
        if (bytes.length>0){
            output.write(bytes);
        }

    }

    private void sendBytes(byte[] bytes) throws IOException{

        // Encryption here on byte array?

        output.writeInt(bytes.length);
        if (bytes.length>0){
            output.write(bytes);
        }

    }


    public void sendFile(String filename) throws Exception{

        byte[] buffer = new byte[256];

        File file = new File(filename);

        InputStream fileReader = new DataInputStream(new FileInputStream(file));

        int readBytes;

        CipherOutputStream cipherOutputStream = crypto.cipherOut(clientSocket.getOutputStream());

        while((readBytes = fileReader.read(buffer)) >0){
            System.out.println(readBytes);
            cipherOutputStream.write(buffer,0,readBytes);

        }

        fileReader.close();
        cipherOutputStream.close();
    }




//    public boolean compress(File f){
//
//        try(
//                FileInputStream fileStream = new FileInputStream(f);
//                FileOutputStream outputStream = new FileOutputStream( f.getName() + ".zip");
//                DeflaterOutputStream compressStream = new DeflaterOutputStream(outputStream);
//        ){
//            byte[] buffer = new byte[BUFFERSIZE];
//
//            int readBytes;
//
//            while ((readBytes = fileStream.read(buffer)) > 0){
//                compressStream.write(buffer, 0, readBytes);
//            }
//
//            return true;
//
//        } catch (IOException e){
//            e.printStackTrace();
//        }
//
//
//    return false;
//
//    }


//    public boolean decompress(String str) throws Exception {
//        if (str == null || str.length() == 0) {
//            return str;
//        }
//        System.out.println("Input String length : " + str.length());
//        GZIPInputStream gis = new GZIPInputStream(new ByteArrayInputStream(str.getBytes("UTF-8")));
//        BufferedReader bf = new BufferedReader(new InputStreamReader(gis, "UTF-8"));
//        String outStr = "";
//        String line;
//        while ((line=bf.readLine())!=null) {
//            outStr += line;
//        }
//        System.out.println("Output String lenght : " + outStr.length());
//        return outStr;
//    }
//
//    public void sendFile(String filename, String caption) throws IOException{
//
//
//        File file = new File(filename);
//
//        if ((compress(file))) {
//
//            OutputStream outputStream = output;
//
//            File compressedFile=new File(file.getName() + ".zip");
//
//            InputStream inputStream = new FileInputStream(file.getName() + ".zip");
//
//            byte[] buffer = new byte[BUFFERSIZE];
//            int readBytes;
//
//            output.writeInt((int)compressedFile.length());
//
//            while ((readBytes = inputStream.read(buffer)) > 0) {
//
//                outputStream.write(buffer, 0, readBytes);
//            }
//
//            outputStream.close();
//            inputStream.close();
//        }
//
//    }
//
//
//    public void recieveFile() throws IOException{
//
//
//        File file = new File(filename);
//
//        if ((compress(file))) {
//
//            OutputStream outputStream = output;
//
//            File compressedFile=new File(file.getName() + ".zip");
//
//            InputStream inputStream = new FileInputStream(file.getName() + ".zip");
//
//            byte[] buffer = new byte[BUFFERSIZE];
//            int readBytes;
//
//            output.writeInt((int)compressedFile.length());
//
//            while ((readBytes = inputStream.read(buffer)) > 0) {
//
//                outputStream.write(buffer, 0, readBytes);
//            }
//
//            outputStream.close();
//            inputStream.close();
//        }
//
//    }


}
