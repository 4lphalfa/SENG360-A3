import javax.crypto.*;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.net.*;
import java.io.*;
import java.util.stream.*;

import javax.xml.bind.DatatypeConverter;
import java.lang.Math;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

public class Server {
    public static void main( String args[] )throws Exception {
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
                    
            // Expect a handshake message
            String initialHandshake = in.readLine();
            byte[] clientPubKeyEnc = commonLib.decodeBase64( initialHandshake );

            KeyFactory keyFact = KeyFactory.getInstance("DH");
            PublicKey clientPubKey = keyFact.generatePublic( new X509EncodedKeySpec( clientPubKeyEnc ) );

            System.out.println( clientPubKey );
            System.out.println();
            
            /*
             * Bob gets the DH parameters associated with Alice's public key.
             * He must use the same parameters when he generates his own key
             * pair.
             */
            DHParameterSpec dhParamFromClientPubKey = ((DHPublicKey)clientPubKey).getParams();
            
            // The Client creates its own DH key pair with 2048-bit key size
            System.out.println("Server: Generate DH keypair ...");
            KeyPairGenerator serverKpairGen = KeyPairGenerator.getInstance("DH");
            serverKpairGen.initialize(dhParamFromClientPubKey);
            KeyPair serverKpair = serverKpairGen.generateKeyPair();
            
            // The Client creates and initializes its DH KeyAgreement object
            System.out.println("Server: Initialization ...");
            KeyAgreement serverKeyAgree = KeyAgreement.getInstance("DH");
            serverKeyAgree.init(serverKpair.getPrivate());
            
            // The Client encodes its public key, and sends it over to The Server.
            byte[] serverPubKeyEnc = serverKpair.getPublic().getEncoded();
            out.println( commonLib.encodeWithBase64( serverPubKeyEnc ) );
            System.out.println( serverPubKeyEnc );
            System.out.println();
            

            serverKeyAgree.doPhase(clientPubKey, true);





            // Start retrieval thread
            MessageListener init = new MessageListener( in, "Client" , serverKeyAgree);
            Thread listener = new Thread( init );
            listener.start();

            System.out.println( "Server started!" );

            String userInput;


            while( ( userInput = stdIn.readLine() ) != null ){ // TODO: fix graphical issue for when messages pop up when typing a message
                // Send off the message
                commonLib.sendMessage( encrypt(serverKeyAgree, userInput), out, "" );
                
            }
        }catch( IOException e ){
            System.out.println( "Exception caught when trying to listen on port " + portNumber + " or listening for a connection" );
            System.out.println( e.getMessage() );
        }
    }
    
    public static String encrypt(KeyAgreement keyAgree, String message) {
        try {
            byte[] serverSharedSecret = keyAgree.generateSecret();
            SecretKeySpec serverAesKey = new SecretKeySpec(serverSharedSecret, 0, 16, "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.ENCRYPT_MODE, serverAesKey);

            byte[] cleartext = message.getBytes();
            byte[] ciphertext = cipher.doFinal(cleartext);
            
            System.out.println("encrypted bytes: ");
            System.out.write(ciphertext);
            System.out.println();
            System.out.println("encrypted string: " + DatatypeConverter.printBase64Binary(ciphertext));

            return DatatypeConverter.printBase64Binary(ciphertext);
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return null;
    }
}
