import java.io.*;
import java.security.*;
import java.util.Base64;

public class Common {
    public KeyPair keys = null;

    public void sendMessage( String input, PrintWriter out, String tags ) {
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

        // TODO: Confidientiality goes here
        // if( tags.toLowerCase().contains("c") )

        System.out.println(toSend);
        System.out.println();
        System.out.println();

        out.println( toSend );
    }

    // Sometimes bytes need to be sent. We'll encode them first so we can use the PrintWriter
    public void sendMessage( byte[] byteInput, PrintWriter out, String tags ) {
        String encodedBytes = Base64.getEncoder().encodeToString( byteInput );
        sendMessage( encodedBytes, out, tags );
    }


    public String encodeWithBase64( byte[] bytes ){
        return Base64.getEncoder().encodeToString( bytes );
    }

    public byte[] decodeBase64( String input ){
        return Base64.getDecoder().decode( input );
    }

    public void createKeysAndSharePublic( PrintWriter out, String tags ) throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        this.keys = keyGen.generateKeyPair();
        byte[] puKeyBytes = keys.getPublic().getEncoded();

        String encoded = encodeWithBase64( puKeyBytes );

        // Remove i from tags. We want to send the key, which won't be signed.
        String newTag = "";
        if( tags.toLowerCase().contains("c") ) newTag += "c";
        if( tags.toLowerCase().contains("a") ) newTag += "a";
        sendMessage( encoded, out, newTag );
    }

    public void startInboxThread( BufferedReader in, String otherUser, String tags, PublicKey puKey ){
        Thread listener;
        if( tags.toLowerCase().contains("i") ){
            listener = new Thread( new MessageListener( in, otherUser, tags, this, puKey ) );
        }else{
            listener = new Thread( new MessageListener( in, otherUser, tags, this ) );
        }

        listener.start();
    }
}