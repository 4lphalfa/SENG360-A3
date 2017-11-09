import javax.crypto.*;
import java.security.*;
import java.security.spec.*;
import java.net.*;
import java.io.*;
import java.util.Base64;


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

            // PrintWriter out = new PrintWriter( clientSocket.getOutputStream(), true );
            PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true );
            BufferedReader in = new BufferedReader( new InputStreamReader( clientSocket.getInputStream() ) );
            BufferedReader stdIn = new BufferedReader( new InputStreamReader( System.in ) );
        ){
            // Prepare common functions library
            Common commonLib = new Common();

            System.out.println( "Server started!" );


            // Expect a handshake message
            byte[] handshakeMessage = Base64.getDecoder().decode( in.readLine() );

            KeyFactory keyFact = KeyFactory.getInstance("RSA");
            PublicKey clientPuKey = keyFact.generatePublic( new X509EncodedKeySpec( handshakeMessage ) );

            System.out.println(clientPuKey);

            // Send your own public key if integrity is set
            commonLib.createKeysAndSharePublic( out, "" );


            // TODO: Server-side authentication goes here


            // Start retrieval thread
            Thread listener = new Thread( new MessageListener( in, "Client" ) );
            listener.start();


            String userInput;

            while( ( userInput = stdIn.readLine() ) != null ){ // TODO: fix graphical issue for when messages pop up when typing a message
                // Send off the message
                commonLib.sendMessage( userInput, out, "" );
            }
        }catch( IOException e ){
            System.out.println( "Exception caught when trying to listen on port " + portNumber + " or listening for a connection" );
            System.out.println( e.getMessage() );
        }catch( NoSuchAlgorithmException e ){
            System.err.println( "Attempted to create a key pair with an invalid algorithm" );
            System.exit( 1 );
        }catch( InvalidKeySpecException e ){
            System.err.println( "Exception caught for Key Spec" );
            System.exit( 1 );
        }
    }
}
