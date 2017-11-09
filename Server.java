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

        String tags = "";
        if( args.length >= 2 ){
            tags = args[1];
        }else if( args.length < 1 ){
            System.err.println( "Usage: java Server <port number> <optional tags: c, i, and/or a>" );
            System.exit( 1 );
        }
         
        int portNumber = Integer.parseInt( args[0] );
         
        try(
            ServerSocket serverSocket = new ServerSocket( Integer.parseInt( args[0] ) );
            Socket clientSocket = serverSocket.accept();

            PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true );
            BufferedReader in = new BufferedReader( new InputStreamReader( clientSocket.getInputStream() ) );
            BufferedReader stdIn = new BufferedReader( new InputStreamReader( System.in ) );
        ){
            // Prepare common functions library
            Common commonLib = new Common();

            System.out.println( "Server started!" );


            // Expect a handshake message
            
            // TODO: Make sure this assumption that the handshakeMessage is always encoded is true
            byte[] handshakeMessage = commonLib.decodeBase64( in.readLine() );

            // If integrity needed
            PublicKey clientPuKey = null;
            if( tags.toLowerCase().contains("i") ){
                KeyFactory keyFact = KeyFactory.getInstance("RSA");
                clientPuKey = keyFact.generatePublic( new X509EncodedKeySpec( handshakeMessage ) );

                // Send your own public key if integrity is set
                commonLib.createKeysAndSharePublic( out, tags);
            }else if( !(new String( handshakeMessage )).contains( "Simple handshake" ) ){
                System.out.println( "Client connecting with Integrity enabled. Both programs must be in the same mode!\nShutting down...");
                System.exit( 1 );
            }


            // TODO: Server-side authentication goes here

            // Start retrieval thread
            commonLib.startInboxThread( in, "Client", tags, clientPuKey );


            String userInput;
            while( ( userInput = stdIn.readLine() ) != null ){ // TODO: fix graphical issue for when messages pop up when typing a message
                // Send off the message
                commonLib.sendMessage( userInput, out, tags );
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
