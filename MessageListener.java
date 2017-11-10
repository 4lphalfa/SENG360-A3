import java.net.*;
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





public class MessageListener implements Runnable{
    private BufferedReader in;
    private String fromWho;
    private String tags;
    private Common commonLib;

    private SecretKeySpec dhKey = null;
    private PublicKey othersKey = null;

    public MessageListener( BufferedReader in, String fromWho, String tags, Common commonLib ){
        this.in = in;
        this.fromWho = fromWho;
        this.tags = tags;
        this.commonLib = commonLib;
        this.dhKey = dhKey;
    }

    // For integrity
    public MessageListener( BufferedReader in, String fromWho, String tags, Common commonLib, PublicKey othersKey ){
        this( in, fromWho, tags, commonLib );
        this.othersKey = othersKey;
    }

    // For confidentiality
    public MessageListener( BufferedReader in, String fromWho, String tags, Common commonLib, SecretKeySpec dhKey ){
        this( in, fromWho, tags, commonLib );
        this.dhKey = dhKey;
    }

    // For confidentiality + integrity
    public MessageListener( BufferedReader in, String fromWho, String tags, Common commonLib, PublicKey othersKey, SecretKeySpec dhKey ){
        this( in, fromWho, tags, commonLib, othersKey );
        this.dhKey = dhKey;
    }

    public void run(){
        String fromMessage;

        try{
            while( ( fromMessage = in.readLine() ) != null ){
                String toDisplay = fromMessage;

                if( this.tags.toLowerCase().contains("c") ){
                    toDisplay = commonLib.decrypt( toDisplay, dhKey );
                }


                // For integrity -- Base64 encoded signatures are expected
                // Order for message is always 'signature, message'
                if( this.tags.toLowerCase().contains("i") && this.othersKey != null ){
                    String[] split = fromMessage.split(" ", 2);

                    if( split.length < 2 ){
                        System.out.println( "!!! Incorrectly formatted message recieved !!!" );
                        continue;
                    }

                    String encodedSig = split[0];
                    toDisplay = split[1];

                    System.out.println("Listened for integrity");
                    System.out.println(toDisplay);

                    byte[] decodedSig = this.commonLib.decodeBase64( encodedSig );

                    try{
                        Signature sigVerifier = Signature.getInstance( "SHA512withRSA" );
                        sigVerifier.initVerify( this.othersKey );
                        sigVerifier.update( toDisplay.getBytes() );

                        boolean authentic = sigVerifier.verify( decodedSig );
                        if( !authentic ){
                            System.out.println( "!!! Following message signature does not match !!!");
                        }
                    }catch( SignatureException e ){
                        System.err.println( "Exception caught for signature" );
                        System.exit( 1 );
                    }catch( NoSuchAlgorithmException e ){
                        System.err.println( "Attempted to create a key pair with an invalid algorithm" );
                        System.exit( 1 );
                    }catch( InvalidKeyException e ){
                        System.err.println( "Exception caught for invalid key" );
                        System.exit( 1 );
                    }
                }else{
                    // TODO: shutdown gracefully with "Not running with integrity" message
                }


                System.out.println( fromWho + ": " + toDisplay );
            }
        }catch( IOException e ){
            System.err.println( "Message reading error!" );
            System.exit( 1 );
        }
    }

}