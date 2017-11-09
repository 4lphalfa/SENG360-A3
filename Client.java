import javax.crypto.*;
import java.security.*;
import java.security.spec.*;
import java.io.*;
import java.net.*;
import java.util.Base64;

public class Client {
    public static void main( String args[] ) {
        
        String tags = "";
        if( args.length >= 3 ){
            tags = args[2];
        }else if( args.length < 2 ){
            System.err.println( "Usage: java Client <host name> <port number> <tags: c, i, and/or a>" );
            System.exit( 1 );
        }

        System.out.println( "Starting Client.java..." );

        String hostName = args[0];
        int portNumber = Integer.parseInt( args[1] );
 
        try(
            Socket serverSocket = new Socket( hostName, portNumber );

            PrintWriter out = new PrintWriter( serverSocket.getOutputStream(), true );
            BufferedReader in = new BufferedReader( new InputStreamReader( serverSocket.getInputStream() ) );
            BufferedReader stdIn = new BufferedReader( new InputStreamReader( System.in ) );
        ){
            // Prepare common functions library
            Common commonLib = new Common();

            System.out.println("Client started!");


            // If integrity, send this as part of handshake
            PublicKey serverPuKey = null;
            if( tags.toLowerCase().contains("i") ){
                commonLib.createKeysAndSharePublic( out, tags );

                // Expect handshake response
                byte[] handshakeMessage = commonLib.decodeBase64( in.readLine() );

                KeyFactory keyFact = KeyFactory.getInstance("RSA");
                serverPuKey = keyFact.generatePublic( new X509EncodedKeySpec( handshakeMessage ) );
            }else{
                // TODO: do this better
                String encoded = commonLib.encodeWithBase64( "Simple handshake".getBytes() );
                commonLib.sendMessage( encoded, out, tags );
            }


            // TODO: Client-side authentication goes here

            // Start retrieval thread
            commonLib.startInboxThread( in, "Server", tags, serverPuKey );

            String userInput;
            while( ( userInput = stdIn.readLine() ) != null ){ // TODO: fix graphical issue for when messages pop up when typing a message
                // Send off the message
                commonLib.sendMessage( userInput, out, tags );
            }

        }catch ( UnknownHostException e ){
            System.err.println( "Don't know about host " + hostName );
            System.exit( 1 );
        }catch( IOException e ){
            System.err.println( "Couldn't get I/O for the connection to " + hostName );
            System.exit( 1 );
        }catch( InvalidKeySpecException e ){
                System.err.println( "Exception caught for Key Spec" );
                System.exit( 1 );
        }catch( NoSuchAlgorithmException e ){
                System.err.println( "Attempted to create a key pair with an invalid algorithm" );
                System.exit( 1 );
        }
    }
}