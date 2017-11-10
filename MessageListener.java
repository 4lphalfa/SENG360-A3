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

import javax.xml.bind.DatatypeConverter;

public class MessageListener implements Runnable{
    private BufferedReader in;
    private String fromWho;
    private KeyAgreement secret;

    public MessageListener(BufferedReader in, String fromWho, KeyAgreement secret){
        this.in = in;
        this.fromWho = fromWho;
        this.secret = secret;
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
    public String decrypt(String ciphertext) {
        try {
            System.out.println("ciphertext: " + ciphertext);
            System.out.println("converted to byte: " + DatatypeConverter.parseBase64Binary(ciphertext));
            SecretKeySpec aesKey = new SecretKeySpec(secret.generateSecret(), 0, 16, "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            AlgorithmParameters aesParams = AlgorithmParameters.getInstance("AES");
            byte[] encodedParams = cipher.getParameters().getEncoded();
            aesParams.init(encodedParams);
            cipher.init(Cipher.DECRYPT_MODE, aesKey, aesParams);
            byte[] recovered = cipher.doFinal(DatatypeConverter.parseBase64Binary(ciphertext));
            
            return new String(recovered);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }
}