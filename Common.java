import java.io.*;
import java.util.Base64;


public class Common {
    public void sendMessage( String input, PrintWriter out, String tags ){
        // Do stuff to input if necessary
        // TODO: Confidientiality goes here
        // if( tags.contains("c") )

        // TODO: Integrity goes here
        // if( tags.toLowerCase().contains("i") )

        out.println( input );
    }

    public String encodeWithBase64( byte[] input ){
        return Base64.getEncoder().encodeToString( input );
    }

    public byte[] decodeBase64( String input ){
        return Base64.getDecoder().decode( input );
    }
}