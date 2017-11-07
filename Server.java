import javax.crypto.*;
import java.net.*;
import java.io.*;

public class Server {
    public static void main( String args[] ){
        // Set-up
        System.out.println( "Starting Server.java..." );

        if ( args.length != 1 ){
            System.err.println( "Usage: java Server <port number>" );
            System.exit( 1 );
        }
         
        int portNumber = Integer.parseInt( args[0] );
         
        try(
            ServerSocket serverSocket = new ServerSocket( Integer.parseInt( args[0] ) );
            Socket clientSocket = serverSocket.accept();

            PrintWriter out = new PrintWriter( clientSocket.getOutputStream(), true );
            BufferedReader in = new BufferedReader( new InputStreamReader( clientSocket.getInputStream() ) );
            BufferedReader stdIn = new BufferedReader( new InputStreamReader( System.in ) );
        ){
            // Prepare common functions library
            Common commonLib = new Common();

            // Start retrieval thread
            Thread listener = new Thread( new MessageListener( in, "Client" ) );
            listener.start();

            System.out.println( "Server started!" );

            String userInput;

            // Expect a handshake message
            // userInput = stdIn.readLine();

            // TODO: Server-side authentication goes here


            while( ( userInput = stdIn.readLine() ) != null ){ // TODO: fix graphical issue for when messages pop up when typing a message
                // Send off the message
                commonLib.sendMessage( userInput, out, "" );
            }
        }catch( IOException e ){
            System.out.println( "Exception caught when trying to listen on port " + portNumber + " or listening for a connection" );
            System.out.println( e.getMessage() );
        }
    }
}
