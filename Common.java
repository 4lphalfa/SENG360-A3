import java.io.*;

public class Common {
    public void sendMessage( String input, PrintWriter out, String tags ){
        // Do stuff to input if necessary
        // TODO: Confidientiality goes here
        // if( tags.contains("c") )

        // TODO: Integrity goes here
        // if( tags.toLowerCase().contains("i") )

        out.println( input );
    }
}