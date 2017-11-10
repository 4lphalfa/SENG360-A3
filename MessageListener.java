import javax.crypto.*;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.net.*;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.io.*;
import java.util.Base64;


import javax.xml.bind.DatatypeConverter;

public class MessageListener implements Runnable{
    private BufferedReader in;
    private String fromWho;
    private SecretKeySpec dhKey;

    public MessageListener(BufferedReader in, String fromWho, SecretKeySpec dhKey){
        this.in = in;
        this.fromWho = fromWho;
        this.dhKey = dhKey;
    }

    public void run(){
        String fromMessage;

        try{
            while( ( fromMessage = in.readLine() ) != null ){
                System.out.println( fromWho + ": " + decrypt(fromMessage) );
            }
        }catch( IOException e ){
            System.err.println( "Message reading error!" );
            System.exit( 1 );
        }
    }
    
    public String getMessage() {
        try {
            String message = in.readLine();
            return message; 
        } catch( IOException e ){
            System.err.println( "Message reading error!" );
            System.exit( 1 );
        }
        return null;
    }
    public String decrypt(String input) {
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