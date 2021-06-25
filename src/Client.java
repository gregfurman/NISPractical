import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;

public class Client {

    /**
     * Main method of program. When run, the client socket will attempt to connect to a server
     * at a given IP and port number.
     * @param args Arguments to the program.
     */
    public static void main(String[] args){

        try {
            Participant client = new Participant(args[0], Integer.parseInt(args[1]));
            Files.createDirectories(Paths.get(client.HOME_DIRECTORY));

            client.start();

        } catch (IOException e){
            System.out.println("No server found.");
        } catch (NoSuchAlgorithmException a){
            System.out.println("Fatal error: RSA key pairs failed to load/generate.");
        }

    }


}
