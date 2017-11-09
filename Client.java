import javax.crypto.*;
import java.security.*;
import java.security.spec.*;
import java.io.*;
import java.net.*;
import java.util.Base64;

public class Client {
    public static void main( String args[] ) {
        if( args.length != 2 ){
            System.err.println( "Usage: java Client <host name> <port number>" );
            System.exit( 1 );
        }

        System.out.println( "Starting Client.java..." );

        String hostName = args[0];
        int portNumber = Integer.parseInt( args[1] );
 
        try(
            Socket serverSocket = new Socket( hostName, portNumber );

            // PrintWriter out = new PrintWriter( serverSocket.getOutputStream(), true );
            PrintWriter out = new PrintWriter( serverSocket.getOutputStream(), true );
            BufferedReader in = new BufferedReader( new InputStreamReader( serverSocket.getInputStream() ) );
            BufferedReader stdIn = new BufferedReader( new InputStreamReader( System.in ) );
        ){
            // Prepare common functions library
            Common commonLib = new Common();

            System.out.println("Client started!");


            // If integrity, send this as part of handshake
            commonLib.createKeysAndSharePublic( out, "" );

            // Expect handshake response
            byte[] handshakeMessage = Base64.getDecoder().decode( in.readLine() );

            KeyFactory keyFact = KeyFactory.getInstance("RSA");
            PublicKey serverPuKey = keyFact.generatePublic( new X509EncodedKeySpec( handshakeMessage ) );

            System.out.println(serverPuKey);
            
            // TODO: Client-side authentication goes here

            // Start retrieval thread
            Thread listener = new Thread( new MessageListener( in, "Server" ) );
            listener.start();



            String userInput;
            while( ( userInput = stdIn.readLine() ) != null ){ // TODO: fix graphical issue for when messages pop up when typing a message
                // Send off the message
                commonLib.sendMessage( userInput, out, "" );
            }
        }catch ( UnknownHostException e ){
            System.err.println( "Don't know about host " + hostName );
            System.exit( 1 );
        }catch( IOException e ){
            System.err.println( "Couldn't get I/O for the connection to " + hostName );
            System.exit( 1 );
        }catch( NoSuchAlgorithmException e ){
            System.err.println( "Attempted to create a key pair with an invalid algorithm" );
            System.exit( 1 );
        }catch( InvalidKeySpecException e ){
            System.err.println( "Exception caught for Key Spec" );
            System.exit( 1 );
        }
    }
}