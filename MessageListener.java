import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.net.*;
import java.io.*;

import javax.xml.bind.DatatypeConverter;

public class MessageListener implements Runnable{
    private BufferedReader in;
    private String fromWho;
    static String key = "Bar12345Bar12345"; // 128 bit key
    static String initVector = "RandomInitVector"; // 16 bytes IV

    public MessageListener(BufferedReader in, String fromWho){
        this.in = in;
        this.fromWho = fromWho;
    }

    public void run(){
        String fromMessage;

        try{
            while( ( fromMessage = in.readLine() ) != null ){
                System.out.println( fromWho + ": " + decrypt(key, initVector, fromMessage) );
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
}