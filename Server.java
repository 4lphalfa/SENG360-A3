import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.net.*;
import java.io.*;
import java.util.stream.*;

import javax.xml.bind.DatatypeConverter;
import java.lang.Math;

public class Server {
    static String key = "Bar12345Bar12345"; // 128 bit key
    static String initVector = "RandomInitVector"; // 16 bytes IV
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
                    
            // Expect a handshake message
            String initialHandshake = in.readLine();
            byte[] clientPubKeyEnc = commonLib.decodeBase64( initialHandshake );

            KeyFactory keyFact = KeyFactory.getInstance("DH");    
            PublicKey clientPubKey = keyFact.generatePublic( new X509EncodedKeySpec( clientPubKeyEnc ) );

            System.out.write( clientPubKey );
            System.out.println();




            // Start retrieval thread
            MessageListener init = new MessageListener( in, "Client" );
            Thread listener = new Thread( init );
            listener.start();

            System.out.println( "Server started!" );

            String userInput;


            while( ( userInput = stdIn.readLine() ) != null ){ // TODO: fix graphical issue for when messages pop up when typing a message
                // Send off the message
                commonLib.sendMessage( encrypt(key, initVector, userInput), out, "" );
                
            }
        }catch( IOException e ){
            System.out.println( "Exception caught when trying to listen on port " + portNumber + " or listening for a connection" );
            System.out.println( e.getMessage() );
        }
    }
    
    public static String encrypt(String key, String initVector, String value) {
        try {
            IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
            SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

            byte[] encrypted = cipher.doFinal(value.getBytes());
            //System.out.println("encrypted string: " + DatatypeConverter.printBase64Binary(encrypted));

            return DatatypeConverter.printBase64Binary(encrypted);
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return null;
    }
    
    public static String decrypt(String key, String initVector, String encrypted) {
        try {
            IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
            SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);

            byte[] original = cipher.doFinal(DatatypeConverter.parseBase64Binary(encrypted));

            //System.out.println(new String(original));
            
            return new String(original);
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return null;
    } 
    
    public static String keyGen(double g, double p, double a) {
        double result = Math.pow(g, a) % p;
        int intResult = (int) result;
        String gen = Integer.toString(intResult);
        System.out.println(intResult);
        return gen;
    }
}
