import javax.crypto.CipherInputStream;
import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.zip.GZIPOutputStream;


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
        }

    }


    public Client(String address,int portNumber) throws IOException {

        try {
            crypto = new Cryptography();
        } catch (NoSuchAlgorithmException a){
            System.out.println("Fatal error: RSA-key generation failed.");
            System.exit(1);
        }


        clientSocket = new Socket(address, portNumber);

        output = new DataOutputStream(clientSocket.getOutputStream());
        input = new DataInputStream(clientSocket.getInputStream());


        keyboardInput = new BufferedReader(new InputStreamReader(System.in));

    }



    private Thread recieverThread(){

        return new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    byte[] byteArray;
                    while ((byteArray = recieveBytes()) != null) {
                        // Decryption!!


                        System.out.println(new String(byteArray));
                    }


                    clientSocket.close();

                } catch (Exception e){
                    e.printStackTrace();
                    System.out.println("Server disconnected");
                    System.exit(0);
                }

            }
        });

    }


    private Thread senderThread(){

        return new Thread(new Runnable() {
            @Override
            public void run() {

                try {
                    String message;
                    System.out.println("Welcome\nPlease enter 1 (to send a message) or 2 (to send a file)");
                    String cmd = keyboardInput.readLine();
                    if (cmd.equals("1")){
                        while (!(message = keyboardInput.readLine()).equals("quit")) {
                            // Encrpytion!!
                            sendBytes(message);

                    }}
                    else if (cmd.equals("2")){
                        System.out.println("Enter file name:\n");
                        String fileName = keyboardInput.readLine();
                        while (!(keyboardInput.readLine()).equals("quit")) {
                            // Encrpytion!!
                            sendFile(fileName);

                        }
                    }

                } catch (Exception e) {
                    e.printStackTrace();
                }

            }
        });


    }

    public void start(){

        try {
            sendBytes(crypto.getPublicKey().getEncoded());

            crypto.setKUb(recieveBytes());

        } catch (Exception e){
            System.out.println("Failed to send public key.");
            e.printStackTrace();
            System.exit(0);
        }


        Thread sender = senderThread();
        Thread reciever = recieverThread();

        sender.start();
        //reciever.start();


    }


    private void sendMessage(String message) throws IOException{
        sendBytes(message.getBytes(StandardCharsets.UTF_8));
    }

    private void sendBytes(String message) throws IOException{

        // Encryption here on byte array?
        byte[] bytes = message.getBytes();
        GZIPOutputStream compressed = new GZIPOutputStream(output);
        output.writeInt(1);
        compressed.write(bytes.length);
        if (bytes.length>0){
            compressed.write(bytes);
        }
        compressed.flush();
        output.close();


    }

    private void sendFile(String fileName) throws IOException{

        // Encryption here on byte array?
        File file = new File(fileName);

        byte[] bytes = new byte[BUFFERSIZE];
        //FileOutputStream fos = new FileOutputStream(fileName + ".gz");
        //GZIPOutputStream compressed = new GZIPOutputStream(fos);
        InputStream in = new FileInputStream(file);

        int count;
        output.writeInt(2);
        output.write(fileName.getBytes());
        //compressed.write(bytes.length);
        while ((count = in.read(bytes)) > 0){
            output.write(bytes, 0, count);
        }
       // compressed.finish();

    }

    private byte[] recieveBytes() throws IOException{

//        Decryption here

        int length = input.readInt();
        byte[] bytes = new byte[length];

        if (length> 0){
            input.readFully(bytes);
        }

        return bytes;
    }


    private void sendBytes(byte[] bytes) throws IOException{

        // Encryption here on byte array?

        output.writeInt(bytes.length);
        if (bytes.length>0){
            output.write(bytes);
        }

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
