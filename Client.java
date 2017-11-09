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
    static String key = "Bar12345Bar12345"; // 128 bit key
    static String initVector = "RandomInitVector"; // 16 bytes IV 
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

            // Start retrieval thread
            Thread listener = new Thread( new MessageListener( in, "Server" ) );
            listener.start();

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
            byte[] serverPubKeyEnc = clientPubKeyEnc;
            
            // The Client uses The Server's public key for the first (and only) phase of its version of the DH protocol.
            KeyFactory clientKeyFac = KeyFactory.getInstance("DH");
            X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(serverPubKeyEnc);
            PublicKey serverPubKey = clientKeyFac.generatePublic(x509KeySpec);
            
            // Before it can do so, it has to instantiate a DH public key from The Server's encoded key material.
            System.out.println("Client: Execute PHASE1 ...");
            clientKeyAgree.doPhase(serverPubKey, true);
            
            // Send handshake message
            // String handshakeMessage = "placeholder";
            // commonLib.sendMessage( handshakeMessage, out, "" );

            // Expect handshake response
            // userInput = stdIn.readLine();
            
            // TODO: Client-side authentication goes here


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
            IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
            // SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");
            SecretKeySpec clientAesKey = new SecretKeySpec(clientSharedSecret, 0, 16, "AES");
            
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, clientAesKey);
            byte[] cleartext = message.getBytes();
            byte[] ciphertext = cipher.doFinal(cleartext);
//            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
//            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
//
//            byte[] encrypted = cipher.doFinal(value.getBytes());
            //System.out.println("encrypted string: " + DatatypeConverter.printBase64Binary(encrypted));

            return DatatypeConverter.printBase64Binary(ciphertext);
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return null;
    }
    
    public static String decrypt(KeyAgreement keyAgree, String ciphertext) {
        try {
            byte[] clientSharedSecret = keyAgree.generateSecret();
            IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
            // SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");
            SecretKeySpec clientAesKey = new SecretKeySpec(clientSharedSecret, 0, 16, "AES");
            
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            
            // Retrieve the parameter that was used, and transfer it to The Client in encoded format
            byte[] encodedParams = cipher.getParameters().getEncoded();
            
            // Instantiate AlgorithmParameters object from parameter encoding
            // obtained from Bob
            AlgorithmParameters aesParams = AlgorithmParameters.getInstance("AES");
            aesParams.init(encodedParams);
            cipher.init(Cipher.DECRYPT_MODE, clientAesKey, aesParams);
            byte[] recovered = cipher.doFinal(DatatypeConverter.parseBase64Binary(ciphertext));
            System.out.println("The message: " + new String(recovered));

            return new String(recovered);
            
//            IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
//            SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");
//
//            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
//            cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
//
//            byte[] original = cipher.doFinal(DatatypeConverter.parseBase64Binary(encrypted));
//
//            System.out.println(new String(original));
//            
//            return new String(original);
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return null;
    } 
}
