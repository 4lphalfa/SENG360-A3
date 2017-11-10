import javax.crypto.*;
import java.security.*;
import java.security.spec.*;
import java.net.*;
import java.io.*;
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

import javax.crypto.*;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.net.*;
import java.io.*;
import java.util.stream.*;

import javax.xml.bind.DatatypeConverter;
import java.lang.Math;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;



public class Server {
    public static void main( String args[] ){
        // Set-up
        System.out.println( "Starting Server.java..." );

        String tags = "";
        if( args.length >= 2 ){
            tags = args[1];
        }else if( args.length < 1 ){
            System.err.println( "Usage: java Server <port number> <optional tags: c, i, and/or a>" );
            System.exit( 1 );
        }
        
        int portNumber = Integer.parseInt( args[0] );
        
        try(
            ServerSocket serverSocket = new ServerSocket( Integer.parseInt( args[0] ) );
            Socket clientSocket = serverSocket.accept();

            PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true );
            BufferedReader in = new BufferedReader( new InputStreamReader( clientSocket.getInputStream() ) );
            BufferedReader stdIn = new BufferedReader( new InputStreamReader( System.in ) );
        ){
            // Prepare common functions library
            Common commonLib = new Common();



            // Expect a handshake message


            SecretKeySpec serverAesKey = null;
            if( tags.toLowerCase().contains("c") ){
                // Expect a confidentiality handshake message
                String[] split = in.readLine().split(" ");
                if( split.length == 2 && split[0].compareTo("C") == 0 ){
                    String confidentialityHandshake = split[1];

                    byte[] clientPubKeyEnc = commonLib.decodeBase64( confidentialityHandshake );

                    KeyFactory keyFact = KeyFactory.getInstance( "DH" );
                    PublicKey clientPubKey = keyFact.generatePublic( new X509EncodedKeySpec( clientPubKeyEnc ) );
                    
                    /*
                    * Bob gets the DH parameters associated with Alice's public key.
                    * He must use the same parameters when he generates his own key
                    * pair.
                    */
                    DHParameterSpec dhParamFromClientPubKey = ( (DHPublicKey)clientPubKey ).getParams();
                    
                    // The Client creates its own DH key pair with 2048-bit key size
                    KeyPairGenerator serverKpairGen = KeyPairGenerator.getInstance("DH");
                    serverKpairGen.initialize(dhParamFromClientPubKey);
                    KeyPair serverKpair = serverKpairGen.generateKeyPair();
                    
                    // The Client creates and initializes its DH KeyAgreement object
                    KeyAgreement serverKeyAgree = KeyAgreement.getInstance("DH");
                    serverKeyAgree.init( serverKpair.getPrivate() );
                    
                    // The Client encodes its public key, and sends it over to The Server.
                    byte[] serverPubKeyEnc = serverKpair.getPublic().getEncoded();
                    out.println( commonLib.encodeWithBase64( serverPubKeyEnc ) );

                    serverKeyAgree.doPhase( clientPubKey, true );

                    serverAesKey = new SecretKeySpec(serverKeyAgree.generateSecret(), 0, 16, "AES");
                }else{
                    System.out.println("Invalid client attempted to connect!");
                }
            }

            
            // TODO: Make sure this assumption that the handshakeMessage is always encoded is true

            // If integrity needed
            PublicKey clientPuKey = null;
            if( tags.toLowerCase().contains("i") ){
                System.out.println("Starting integrity");
                // Wait for integrity handshake
                String input = in.readLine();

                if( tags.toLowerCase().contains("c") ){
                    input = commonLib.decrypt( input, serverAesKey );
                }

                String[] split = input.split(" ");
                if( split.length == 2 && split[0].compareTo("I") == 0 ){
                    String integrityHandshake = split[1];

                    KeyFactory keyFact = KeyFactory.getInstance("RSA");
                    clientPuKey = keyFact.generatePublic( new X509EncodedKeySpec( commonLib.decodeBase64( integrityHandshake ) ) );

                    // Send your own public key
                    String encodedPublicKey = commonLib.createKeysAndEncodePublicKey( out );

                    String newTags = "";
                    if( tags.toLowerCase().contains("c") ){
                        newTags += "c";
                    }
                    commonLib.sendMessage( encodedPublicKey, out, newTags, serverAesKey );
                }else{
                    System.out.println("Invalid client attempted to connect!");
                }
            }

            if( tags.toLowerCase().contains("a") ) { //Authentication chosen as the securtiy option
                boolean authFlag = false;

                while( !authFlag ) { //While the client hasn't authenticated loop waiting for it
                    if(in.readLine().trim().equals("A")) { //If client security option matches continue with authenication
                        commonLib.sendMessage( "Correct Mode", out, "", serverAesKey ); //Let the client know it is in correct mode
                        System.out.println("Authenticating Client...");
                        boolean authenticated = authenticateClient(in, out, commonLib, serverAesKey ); //try and authenticate the client
                    
                        if(authenticated) { //if the client has been authenticated set bool to break loop and go to normal chat service
                            authFlag = true;
                        } else { //if the client has not been authenticate let it know, dont break out of the loop, continue to wait for authentic client
                            System.err.println("Client Failed to Authenticate");
                            commonLib.sendMessage("Authentication Failed. Goodbye.", out, "", serverAesKey);
                        }
                    } else { //else client security option is incorrect, let the client know
                        commonLib.sendMessage( "Incorrect Mode", out, "", serverAesKey);
                    }
                }
            }	
            
            
            // else if( !(new String( initialHandshake )).contains( "Simple handshake" ) ){
            //     System.out.println( "Client connecting with Integrity enabled. Both programs must be in the same mode!\nShutting down...");
            //     System.exit( 1 );
            // }


            // TODO: Server-side authentication goes here

            // Start retrieval thread
            commonLib.startInboxThread( in, "Client", tags, clientPuKey, serverAesKey );

            System.out.println( "Server started!" );



            String userInput;
            while( ( userInput = stdIn.readLine() ) != null ){ // TODO: fix graphical issue for when messages pop up when typing a message
                // Send off the message
                commonLib.sendMessage( userInput, out, tags, serverAesKey );
            }

        }catch( IOException e ){
            System.out.println( "Exception caught when trying to listen on port " + portNumber + " or listening for a connection" );
            System.out.println( e.getMessage() );
        }catch( NoSuchAlgorithmException e ){
            System.err.println( "Attempted to create a key pair with an invalid algorithm" );
            System.exit( 1 );
        }catch( InvalidKeySpecException e ){
            System.err.println( "Exception caught for Key Spec" );
            System.exit( 1 );
        }catch( InvalidKeyException e ){
                System.err.println( "Invalid key" );
                System.exit( 1 );
        }catch( InvalidAlgorithmParameterException e ){
                System.err.println( "Invalid Algorithm Parameter!" );
                System.exit( 1 );
        }
    }

    private static boolean authenticateClient( BufferedReader in, PrintWriter out, Common commonLib, SecretKeySpec serverAesKey ) {

        try {
            
            String userPass = in.readLine();
            String[] userPassSplit = userPass.split(" ");
            MessageDigest hashFunc = MessageDigest.getInstance( "SHA-256" );

            if( userPassSplit.length != 2 ) {
                System.out.println("Incorrect information sent from client, closing");
                System.exit( 1 );
            }
            String username = userPassSplit[0];
            String password = userPassSplit[1];
            String cipheredSecret = "";

            String encodedUsername = Base64.getEncoder().encodeToString(hashFunc.digest(username.getBytes())); //get an encoded, hashed username to compare to user list
            String encodedPass = Base64.getEncoder().encodeToString(hashFunc.digest(password.getBytes())); //get an encoded, hashed password to compare to user list

            FileReader fReader = new FileReader( "SecureFolder/AuthenticatedUsers.txt" );
            BufferedReader bReader = new BufferedReader(fReader);

            String curLine = "";

            while( (curLine = bReader.readLine()) != null ) {		
                String[] splitString = curLine.split(" ");
                
                if( encodedUsername.equals(splitString[0]) && encodedPass.equals(splitString[1]) ) {
                    cipheredSecret = splitString[2];
                    break;
                }
            }

            bReader.close();

            if( cipheredSecret == "" ) { //if we didnt find a cipheredsecret then we didnt find the user and authentication has failed
                System.err.println("User not found");
                return false;
            }

            commonLib.sendMessage( cipheredSecret, out, "", serverAesKey );

            String clientResponse = in.readLine();
            if(clientResponse.equals("Authenticated")) {
                System.out.println("Authenticated Client, Begin Chat");
                System.out.println("________________________________");
            } else {
                return false;
            }


        } catch( NoSuchAlgorithmException e ) {
            System.err.println( e );
            System.exit( 1 );
        } catch( IOException e ){
            System.err.println( e );
            System.exit( 1 );
        }


        return true;
    }
}
