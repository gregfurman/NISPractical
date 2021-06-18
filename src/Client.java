import javax.crypto.CipherInputStream;
import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;


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
                } catch (Exception e) {
                    System.out.println("Fatal error: decryption failed.");
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
            byte [] senderCertificate = recieveBytes();
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

            Thread sender = senderThread();
            Thread reciever = recieverThread();

            sender.start();
            reciever.start();
        
        } catch (Exception e){
            System.out.println("Failed to send Certificate.");
            e.printStackTrace();
        }


    }

    private byte[] encryptMessage(String message) throws Exception{

        SecretKey key = crypto.generateSecretKey();
        IvParameterSpec iv = crypto.generateInitialisationVector();

        byte[] encryptedMessage = crypto.encryptWithSecretKey(message, key,iv);
        byte[] encryptedKey = crypto.encryptSecretKey(key);

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
        outputStream.write( encryptedKey );
        outputStream.write(iv.getIV());
        outputStream.write( encryptedMessage );

        return outputStream.toByteArray();

    }

    private byte[] decryptMessage(byte[] data) throws Exception{

        SecretKey key = crypto.decryptSecretKey(Arrays.copyOfRange(data,0,256));
        IvParameterSpec IV = new IvParameterSpec(Arrays.copyOfRange(data,256,256+16));
        byte[] decryptedMessage = crypto.decryptWithSecretKey(Arrays.copyOfRange(data,256+16,data.length),key,IV);
        return decryptedMessage;


    }

    private void sendBytes(String message) throws IOException{

        byte[] bytes = message.getBytes();

        if (bytes.length>0){
            output.write(bytes);
        }
        output.flush();
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

    private void sendBytes(byte[] bytes) throws IOException{

        // Encryption here on byte array?


        if (bytes.length>0){
            output.write(bytes);
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
