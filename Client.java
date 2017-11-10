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
import java.util.Base64;


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

            // Expect a handshake message
            String initialHandshake = in.readLine();
            byte[] serverPubKeyEnc = commonLib.decodeBase64( initialHandshake );
            
            KeyFactory keyFact = KeyFactory.getInstance("DH");
            PublicKey serverPubKey = keyFact.generatePublic( new X509EncodedKeySpec( serverPubKeyEnc ) );
            
            clientKeyAgree.doPhase(serverPubKey, true);

            SecretKeySpec clientAesKey = new SecretKeySpec(clientKeyAgree.generateSecret(), 0, 16, "AES");


            // Start retrieval thread
            MessageListener init = new MessageListener( in, "Server", clientAesKey);
            Thread listener = new Thread(init );
            listener.start(); 
            

            System.out.println("Client started!");


            String userInput;
            while( ( userInput = stdIn.readLine() ) != null ){ // TODO: fix graphical issue for when messages pop up when typing a message
                // Send off the message
                commonLib.sendMessage( encrypt(clientAesKey, userInput), out, "" );
            }
        }catch ( UnknownHostException e ){
            System.err.println( "Don't know about host " + hostName );
            System.exit( 1 );
        }catch( IOException e ){
            System.err.println( "Couldn't get I/O for the connection to " + hostName );
            System.exit( 1 );
        }
        
    }
    
    public static String encrypt(SecretKeySpec clientAesKey, String message) {
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

            cipher.init(Cipher.ENCRYPT_MODE, clientAesKey);

            byte[] encodedCipherParameters = cipher.getParameters().getEncoded();
            String base64EncodedCipherParameters = Base64.getEncoder().encodeToString( encodedCipherParameters );

            byte[] cleartext = message.getBytes();
            byte[] ciphertext = cipher.doFinal(cleartext);

            String toSend = base64EncodedCipherParameters + " " + Base64.getEncoder().encodeToString(ciphertext);


            return toSend;
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return null;
    }
}
