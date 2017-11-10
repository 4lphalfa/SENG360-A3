import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.*;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

import javax.xml.bind.DatatypeConverter;

public class Client {
    public static void main( String args[] ) throws Exception {
        if( args.length != 2 ){
            System.err.println( "Usage: java Client <host name> <port number>" );
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
            
            // The Client creates its own DH key pair with 2048-bit key size
            System.out.println("Client: Generate DH keypair ...");
            KeyPairGenerator clientKpairGen = KeyPairGenerator.getInstance("DH");
            clientKpairGen.initialize(2048);
            KeyPair clientKpair = clientKpairGen.generateKeyPair();
            
            // The Client creates and initializes its DH KeyAgreement object
            System.out.println("Client: Initialization ...");
            KeyAgreement clientKeyAgree = KeyAgreement.getInstance("DH");
            clientKeyAgree.init(clientKpair.getPrivate());
            
            // The Client encodes its public key, and sends it over to The Server.
            byte[] clientPubKeyEnc = clientKpair.getPublic().getEncoded();
            out.println( commonLib.encodeWithBase64( clientPubKeyEnc ) );
            System.out.println( clientPubKeyEnc );
            System.out.println();

            // Expect a handshake message
            String initialHandshake = in.readLine();
            byte[] serverPubKeyEnc = commonLib.decodeBase64( initialHandshake );
            
            KeyFactory keyFact = KeyFactory.getInstance("DH");   
            PublicKey serverPubKey = keyFact.generatePublic( new X509EncodedKeySpec( serverPubKeyEnc ) );
            
            clientKeyAgree.doPhase(serverPubKey, true);
            // Send the clientPubKeyEnc to server, encode with base64
            
            


            // byte[] serverPubKeyEnc = clientPubKeyEnc;
            
            // The Client uses The Server's public key for the first (and only) phase of its version of the DH protocol.
            //KeyFactory clientKeyFac = KeyFactory.getInstance("DH");
            //X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(serverPubKeyEnc);
            //PublicKey serverPubKey = clientKeyFac.generatePublic(x509KeySpec);
            
            // // Before it can do so, it has to instantiate a DH public key from The Server's encoded key material.
            // System.out.println("Client: Execute PHASE1 ...");
            //clientKeyAgree.doPhase(serverPubKey, true);


            // Start retrieval thread
            MessageListener init = new MessageListener( in, "Server", clientKeyAgree);
            Thread listener = new Thread(init );
            listener.start(); 
            

            String userInput;
            while( ( userInput = stdIn.readLine() ) != null ){ // TODO: fix graphical issue for when messages pop up when typing a message
                // Send off the message
                commonLib.sendMessage( encrypt(clientKeyAgree, userInput), out, "" );
            }
        }catch ( UnknownHostException e ){
            System.err.println( "Don't know about host " + hostName );
            System.exit( 1 );
        }catch( IOException e ){
            System.err.println( "Couldn't get I/O for the connection to " + hostName );
            System.exit( 1 );
        }
        
    }
    
    public static String encrypt(KeyAgreement keyAgree, String message) {
        try {
            byte[] clientSharedSecret = keyAgree.generateSecret();
            SecretKeySpec clientAesKey = new SecretKeySpec(clientSharedSecret, 0, 16, "AES");
            
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, clientAesKey);
            byte[] cleartext = message.getBytes();
            byte[] ciphertext = cipher.doFinal(cleartext);

            System.out.println("encrypted bytes: " + ciphertext);
            System.out.println("encrypted string: " + DatatypeConverter.printBase64Binary(ciphertext));

            return DatatypeConverter.printBase64Binary(ciphertext);
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return null;
    }
}
