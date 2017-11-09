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
						System.out.println("Authenticate"); // TODO: remove this debugging println
						boolean authenticated = authenticateClient(in, out); //try and authenticate the client
					
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
					
			System.out.println("Hm");

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

	private static boolean authenticateClient( BufferedReader in, PrintWriter out ) {

		try {
			
			String encodedHashedStr = in.readLine();
			System.out.println("Server-Side");
			System.out.println(encodedHashedStr);
			String[] encodedHashedInfo = encodedHashedStr.split("\\s+");
			String hashedUsername = new String(Base64.getDecoder().decode(encodedHashedInfo[0]));
			String hashedPassword = new String(Base64.getDecoder().decode(encodedHashedInfo[1]));
			String hashedSecret = "";
			FileReader fReader = new FileReader( "SecureFolder/AuthenticatedUsers.txt" );
			BufferedReader bReader = new BufferedReader(fReader);
			int i = 0;

			while(bReader.readLine() != null) {
				String curLine = bReader.readLine();
				String[] splitString = curLine.split("\\s+");
				System.out.println(i);
				System.out.println(hashedUsername);
				System.out.println(splitString[0]);
				System.out.println(hashedUsername);
				System.out.println(splitString[1]);				
				if( hashedUsername.equals(splitString[0]) && hashedPassword.equals(splitString[1]) ) {
					hashedSecret = splitString[2];
					break;
				}
				i++;
			}
			bReader.close();

			if(hashedSecret != "") {
				System.out.println(hashedSecret);
				System.out.println(hashedSecret.getBytes());
				//commonLib.sendMessage( Base64.getEncoder().encodeToString(hashedSecret.getBytes()), out, "" );
			} else {
				System.err.println( "User not found" );
				return false;
			}

		} catch( IOException e ){
		    System.err.println( e );
		    System.exit( 1 );
		}


		return true;
	}
}
