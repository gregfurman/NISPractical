import java.io.File;

public class test {

    public static void main (String[] args){


        try {
            Cryptography cryptography = new Cryptography();

            File file_1 = new File("prac.pdf");

            File file_2 = new File("prac(1).pdf");

            byte[] hash = cryptography.sha512File(file_1);

            System.out.println(cryptography.checkHash(file_1,hash));






        } catch (Exception e){
            e.printStackTrace();
        }



    }


}
