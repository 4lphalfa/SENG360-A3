import javax.crypto.*;
import java.net.*;
import java.io.*;
import java.security.*;
import java.util.Base64;
import java.nio.file.*;
import java.util.*;

public class Server {

	public static void main( String args[] ){
		// Set-up
		System.out.println( "Starting Server.java..." );

		if ( args.length != 2 ) {
		    System.err.println( "Usage: java Server <port number> <security option>" );
		    System.err.println( "Option: C for Confidentiality, I for Integrity, A for Authentication, All for all options" );
		    System.exit( 1 );
		}

		int portNumber = Integer.parseInt( args[0] );
		String option = args[1].trim();

		if( !"C".equals(option) && !"I".equals(option) && !"A".equals(option) && !"All".equals(option) ) {
			System.err.println( "Unknown option specified" );
			System.err.println( "Usage: java Server <port number> <security option>" );
			System.err.println( "Options: C for Confidentiality, I for Integrity, A for Authentication, All for all");
			System.exit( 1 );		
		}
		 
		try(
		    ServerSocket serverSocket = new ServerSocket( Integer.parseInt( args[0] ) );
		    Socket clientSocket = serverSocket.accept();

		    PrintWriter out = new PrintWriter( clientSocket.getOutputStream(), true );
		    BufferedReader in = new BufferedReader( new InputStreamReader( clientSocket.getInputStream() ) );
		    BufferedReader stdIn = new BufferedReader( new InputStreamReader( System.in ) );
		) {
		    	// Prepare common functions library
		    Common commonLib = new Common();



		    System.out.println( "Server started!" );

		    String userInput;

			// TODO: Make this a switch statement when the other security options are impliemented
		    if( "A".equals(option) ) { //Authentication chosen as the securtiy option
		    	boolean authFlag = false;

		    	while( !authFlag ) { //While the client hasn't authenticated loop waiting for it
		    		userInput = in.readLine(); //expect input from client with security mode

					if(userInput.trim().equals(option)) { //If client security option matches continue with authenication
						commonLib.sendMessage( "Correct Mode", out, "" ); //Let the client know it is in correct mode
						System.out.println("Authenticating Client...");
						boolean authenticated = authenticateClient(in, out, commonLib); //try and authenticate the client
					
						if(authenticated) { //if the client has been authenticated set bool to break loop and go to normal chat service
							authFlag = true;							
						} else { //if the client has not been authenticate let it know, dont break out of the loop, continue to wait for authentic client
							System.err.println("Client Failed to Authenticate");
							commonLib.sendMessage("Authentication Failed", out, "");
						}
					} else { //else client security option is incorrect, let the client know
						commonLib.sendMessage( "Incorrect Mode", out, "");
					}
		    	}
		    }	

		    // Start retrieval thread
		    Thread listener = new Thread( new MessageListener( in, "Client" ) );
			listener.start();


		    while( ( userInput = stdIn.readLine() ) != null ){ // TODO: fix graphical issue for when messages pop up when typing a message
		       	// Send off the message
		     	commonLib.sendMessage( userInput, out, "" );
		    }
		} catch( IOException e ) {
		    System.out.println( "Exception caught when trying to listen on port " + portNumber + " or listening for a connection" );
		    System.out.println( e.getMessage() );
		}
	}

	private static boolean authenticateClient( BufferedReader in, PrintWriter out, Common commonLib ) {

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

<<<<<<< HEAD
			String curLine = "";

			while( (curLine = bReader.readLine()) != null ) {		
=======
			while( bReader.readLine() != null ) {
				String curLine = bReader.readLine();
				System.out.println(curLine);

>>>>>>> 4dc9913657b157c2185f5528c97859485c6ab832
				String[] splitString = curLine.split(" ");

                for(int i = 0; i < splitString.length; i++){
                    System.out.println(splitString[i]);
                }
				
<<<<<<< HEAD
				if( encodedUsername.equals(splitString[0]) && encodedPass.equals(splitString[1]) ) {
=======
                System.out.println("End test");


				if( encodedUsername == splitString[0] && encodedPass == splitString[1] ) {
					System.out.println(curLine);
					System.out.println(splitString[0]);
					System.out.println(splitString[1]);
					System.out.println(splitString[2]);
>>>>>>> 4dc9913657b157c2185f5528c97859485c6ab832
					cipheredSecret = splitString[2];
					break;
				}
			}

			bReader.close();

			if( cipheredSecret == "" ) { //if we didnt find a cipheredsecret then we didnt find the user and authentication has failed
				System.err.println("User not found");
				return false;
			}

			commonLib.sendMessage( cipheredSecret, out, "" );

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
