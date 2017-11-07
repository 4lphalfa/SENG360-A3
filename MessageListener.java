import java.net.*;
import java.io.*;

public class MessageListener implements Runnable{
    private BufferedReader in;
    private String fromWho;

    public MessageListener(BufferedReader in, String fromWho){
        this.in = in;
        this.fromWho = fromWho;
    }

    public void run(){
        String fromMessage;

        try{
            while( ( fromMessage = in.readLine() ) != null ){
                System.out.println( fromWho + ": " + fromMessage );
            }
        }catch( IOException e ){
            System.err.println( "Message reading error!" );
            System.exit( 1 );
        }
    }

}