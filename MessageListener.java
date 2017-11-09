import java.net.*;
import java.io.*;
import java.security.*;
import java.util.Base64;




public class MessageListener implements Runnable{
    private BufferedReader in;
    private String fromWho;
    private String tags;
    private Common commonLib;

    private PublicKey othersKey = null;

    public MessageListener( BufferedReader in, String fromWho, String tags, Common commonLib ){
        this.in = in;
        this.fromWho = fromWho;
        this.tags = tags;
        this.commonLib = commonLib;
    }

    // For integrity
    public MessageListener( BufferedReader in, String fromWho, String tags, Common commonLib, PublicKey othersKey ){
        this( in, fromWho, tags, commonLib );
        this.othersKey = othersKey;
    }

    public void run(){
        String fromMessage;

        try{
            while( ( fromMessage = in.readLine() ) != null ){
                String toDisplay = fromMessage;

                // For integrity -- Base64 encoded signatures are expected
                // Order for message is always 'signature message'
                if( this.tags.toLowerCase().contains("i") && this.othersKey != null ){
                    String[] split = fromMessage.split(" ", 2);

                    if( split.length < 2 ){
                        System.out.println( "!!! Incorrectly formatted message recieved !!!" );
                        continue;
                    }

                    String encodedSig = split[0];
                    toDisplay = split[1];

                    byte[] decodedSig = this.commonLib.decodeBase64( encodedSig );

                    try{
                        Signature sigVerifier = Signature.getInstance( "SHA512withRSA" );
                        sigVerifier.initVerify( this.othersKey );
                        sigVerifier.update( toDisplay.getBytes("UTF-8") );

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