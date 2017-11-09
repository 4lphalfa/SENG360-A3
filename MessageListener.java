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

    public static String decrypt(String key, String initVector, String cyphertext) {
        // Retrieve the parameter that was used, and transfer it to Alice in
        // encoded format
        byte[] encodedParams = serverCipher.getParameters().getEncoded();
        
        /*
         * Let's turn over to Bob. Bob has received Alice's public key
         * in encoded format.
         * He instantiates a DH public key from the encoded key material.
         */
        KeyFactory serverKeyFac = KeyFactory.getInstance("DH");
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(clientPubKeyEnc);

        PublicKey clientPubKey = serverKeyFac.generatePublic(x509KeySpec);

        /*
         * The Server gets the DH parameters associated with The Client's public key.
         * It must use the same parameters when it generates its own key pair.
         */
        DHParameterSpec dhParamFromClientPubKey = ((DHPublicKey)clientPubKey).getParams();
        
        // The Server creates its own DH key pair
        System.out.println("The Server: Generate DH keypair ...");
        KeyPairGenerator serverKpairGen = KeyPairGenerator.getInstance("DH");
        serverKpairGen.initialize(dhParamFromClientPubKey);
        KeyPair serverKpair = serverKpairGen.generateKeyPair();

        // The Server creates and initializes his DH KeyAgreement object
        System.out.println("Server: Initialization ...");
        KeyAgreement serverKeyAgree = KeyAgreement.getInstance("DH");
        serverKeyAgree.init(serverKpair.getPrivate());

        // The Server encodes its public key, and sends it over to The Client.
        byte[] serverPubKeyEnc = serverKpair.getPublic().getEncoded();
        
        /*
         * Bob uses Alice's public key for the first (and only) phase
         * of his version of the DH
         * protocol.
         */
        System.out.println("Server: Execute PHASE1 ...");
        serverKeyAgree.doPhase(clientPubKey, true);
        try {
            /*
             * Alice decrypts, using AES in CBC mode
             */

            // Instantiate AlgorithmParameters object from parameter encoding
            // obtained from Bob
            AlgorithmParameters aesParams = AlgorithmParameters.getInstance("AES");
            aesParams.init(encodedParams);

            SecretKeySpec serverAesKey = new SecretKeySpec(aliceSharedSecret, 0, 16, "AES");
            
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, serverAesKey, aesParams);
            byte[] recovered = cipher.doFinal(ciphertext);
            System.out.println("The message: " + new String(recovered));
            
            return new String(recovered);
            
//            IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
//            SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");
//
//            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
//            cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
//
//            byte[] original = cipher.doFinal(DatatypeConverter.parseBase64Binary(encrypted));

            //System.out.println(new String(original));
            
            return new String(original);
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return null;
    }  
}