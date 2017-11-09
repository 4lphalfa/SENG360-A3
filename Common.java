import java.io.*;
import java.security.*;
import java.util.Base64;

public class Common {
    public KeyPair keys = null;

    public void sendMessage( String input, PrintWriter out, String tags ){
        // Do stuff to input if necessary
        // TODO: Confidientiality goes here
        // if( tags.contains("c") )

        // TODO: Integrity goes here
        // if( tags.toLowerCase().contains("i") )

        out.println( input );
    }


    // Sometimes bytes need to be sent. We'll encode them first so we can use the PrintWriter
    public void sendMessage( byte[] byteInput, PrintWriter out, String tags ){
        String encodedBytes = Base64.getEncoder().encodeToString( byteInput );
        sendMessage( encodedBytes, out, tags );
    }


    public void createKeysAndSharePublic( PrintWriter out, String tags ) throws NoSuchAlgorithmException {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            KeyPair keys = keyGen.generateKeyPair();
            byte[] puKeyBytes = keys.getPublic().getEncoded();

            System.out.println(keys.getPublic());

            String encoded = Base64.getEncoder().encodeToString(puKeyBytes);
            sendMessage( encoded, out, tags );
    }
}