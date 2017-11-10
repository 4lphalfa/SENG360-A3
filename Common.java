import java.io.*;
import java.security.*;
import java.util.Base64;

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


public class Common {
    public KeyPair keys = null;

    public void sendMessage( String input, PrintWriter out, String tags, SecretKeySpec aesKey ) {
        // Do stuff to input if necessary
        String toSend = input;

        // Integrity
        if( tags.toLowerCase().contains("i") && this.keys != null ){
            try{
                Signature sig = Signature.getInstance( "SHA512withRSA" );
                sig.initSign( this.keys.getPrivate() );
                sig.update( input.getBytes("UTF-8") );
                byte[] sigToSend = sig.sign();
                toSend = encodeWithBase64( sigToSend );
                toSend += " ";
                toSend += input;
            }catch( NoSuchAlgorithmException e ){
                System.err.println( "Attempted to create a key pair with an invalid algorithm" );
                System.exit( 1 );
            }catch( InvalidKeyException e ){
                System.err.println( "Exception caught for invalid key" );
                System.exit( 1 );
            }catch( SignatureException e ){
                System.err.println( "Exception caught for signature" );
                System.exit( 1 );
            }catch( UnsupportedEncodingException e ){
                System.err.println( "Exception caught for unsupported encoding" );
                System.exit( 1 );
            }
        }

        // Confidentiality
        if( tags.toLowerCase().contains("c") && aesKey != null ){
            toSend = encrypt( aesKey, toSend );
        }

        System.out.println(toSend);
        System.out.println();
        System.out.println();

        out.println( toSend );
    }

    // Sometimes bytes need to be sent. We'll encode them first so we can use the PrintWriter
    public void sendMessage( byte[] byteInput, PrintWriter out, String tags, SecretKeySpec aesKey ) {
        String encodedBytes = Base64.getEncoder().encodeToString( byteInput );
        sendMessage( encodedBytes, out, tags, aesKey );
    }

    public void sendMessage( byte[] byteInput, PrintWriter out, String tags ) {
        sendMessage( byteInput, out, tags, null );
    }


    public String encodeWithBase64( byte[] bytes ){
        return Base64.getEncoder().encodeToString( bytes );
    }

    public byte[] decodeBase64( String input ){
        return Base64.getDecoder().decode( input );
    }

    // public void createKeysAndSharePublic( PrintWriter out, String tags ) throws NoSuchAlgorithmException {
    //     KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
    //     this.keys = keyGen.generateKeyPair();
    //     byte[] puKeyBytes = keys.getPublic().getEncoded();

    //     String encoded = encodeWithBase64( puKeyBytes );

    //     // Remove i from tags. We want to send the key, which won't be signed.
    //     String newTag = "";
    //     if( tags.toLowerCase().contains("c") ) newTag += "c";
    //     if( tags.toLowerCase().contains("a") ) newTag += "a";
    //     sendMessage( encoded, out, newTag );
    // }

    public String createKeysAndEncodePublicKey( PrintWriter out ) throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        this.keys = keyGen.generateKeyPair();
        byte[] puKeyBytes = keys.getPublic().getEncoded();

        return encodeWithBase64( puKeyBytes );
    }

    public void startInboxThread( BufferedReader in, String otherUser, String tags, PublicKey puKey, SecretKeySpec dhKey ){
        Thread listener;

        if( tags.toLowerCase().contains("c") && tags.toLowerCase().contains("i") ){
            listener = new Thread( new MessageListener( in, otherUser, tags, this, puKey, dhKey ) );
        }else if( tags.toLowerCase().contains("c") ){
            listener = new Thread( new MessageListener( in, otherUser, tags, this, dhKey ) );
        }else if( tags.toLowerCase().contains("i") ){
            listener = new Thread( new MessageListener( in, otherUser, tags, this, puKey ) );
        }else{
            listener = new Thread( new MessageListener( in, otherUser, tags, this ) );
        }

        listener.start();
    }

    public static String encrypt(SecretKeySpec aesKey, String message) {
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

            cipher.init(Cipher.ENCRYPT_MODE, aesKey);

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

    public String decrypt( String input, SecretKeySpec dhKey ) {
        try {
            String[] strings = input.split(" ", 2);
            String base64EncodedParameters = strings[0];
            String ciphertext = strings[1];

            byte[] encodedParams = Base64.getDecoder().decode( base64EncodedParameters );

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

            AlgorithmParameters aesParams = AlgorithmParameters.getInstance("AES");
            aesParams.init(encodedParams);
            cipher.init(Cipher.DECRYPT_MODE, dhKey, aesParams);
            byte[] recovered = cipher.doFinal(Base64.getDecoder().decode(ciphertext.getBytes()));
            
            return new String(recovered);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }
}