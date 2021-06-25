import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;

public class Server {

    /**
     * Main method of program. When run, the server socket will await a client
     * connection.
     * @param args Arguments to the program.
     */
    public static void main(String[] args){

        try {
            Participant server = new Participant(Integer.parseInt(args[0]));
            Files.createDirectories(Paths.get(server.HOME_DIRECTORY));

            server.start();

        } catch (IOException e){
            System.out.println("Error in client connecting to server.");
        } catch (NoSuchAlgorithmException a){
            System.out.println("Fatal error: RSA key pairs failed to load/generate.");
        }

    }

}
