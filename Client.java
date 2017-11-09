import javax.crypto.*;
import java.net.*;
import java.io.*;
import java.security.*;
import java.util.Base64;
import java.nio.file.*;

public class Client {
	public static void main( String args[] ) {
		
		System.out.println( "Starting Client.java..." );

		if( args.length != 3 ) {
	    	System.err.println( "Usage: java Client <host name> <port number> <security option>" );
	    	System.err.println( "Options: C for Confidentiality, I for Integrity, A for Authentication, All for all 3" );
	    	System.exit( 1 );
		}

		String hostName = args[0];
		int portNumber = Integer.parseInt( args[1] );
	 	String option = args[2].trim();

		if( !"C".equals(option) && !"I".equals(option) && !"A".equals(option) && !"All".equals(option) ) {
			System.err.println( "Unknown option specified" );
			System.err.println( "Usage: java Server <port number> <security option>" );
			System.err.println( "Options: C for Confidentiality, I for Integrity, A for Authentication, All for all");
			System.exit( 1 );		
		}

		try(
		    Socket serverSocket = new Socket( hostName, portNumber );

		    PrintWriter out = new PrintWriter( serverSocket.getOutputStream(), true );
		    BufferedReader in = new BufferedReader( new InputStreamReader( serverSocket.getInputStream() ) );
		    BufferedReader stdIn = new BufferedReader( new InputStreamReader( System.in ) );
		) {
		 	// Prepare common functions library
		    Common commonLib = new Common();
		    String userInput;
		    	
		    // Start retrieval thread
		    Thread listener = new Thread( new MessageListener( in, "Server" ) );
		    listener.start();

		    System.out.println("Client started!");

			// TODO: Make this a switch statement when the other security options are impliemented
		    if( "A".equals(option) ) { // Authentication chosen as the securtiy option
		    	
		    	commonLib.sendMessage( option, out, "" ); // Send the option to the server
		    	userInput = in.readLine(); // read back the respose from the server 
				
				if( "Correct Mode".equals( userInput.trim() ) ) { // if the server responds that the client is in a matching mode, procede with authentication
					System.out.println("In Correct Mode"); // TODO: remove this debugging println
					boolean authenticated = authenticateWServer( in, stdIn, out, commonLib );

					if( !authenticated ) { // if the authentication fails close the client
						System.err.println("Could not authenticate with Server");
						System.exit( 1 );
					}
				} else {
					System.err.println( "Client selected security option does not match server setting, please try agian" );
					System.exit( 1 );
				}
		    }


	    	while( ( userInput = stdIn.readLine() ) != null ){ // TODO: fix graphical issue for when messages pop up when typing a message
	        	// Send off the message
	        	commonLib.sendMessage( userInput, out, "" );
	    	}
		} catch ( UnknownHostException e ){
		    System.err.println( "Don't know about host " + hostName );
		    System.exit( 1 );
		} catch( IOException e ){
		    System.err.println( "Couldn't get I/O for the connection to " + hostName );
		    System.exit( 1 );
		}
	}

	/**
	*	Function called to prompt the user for a user name, password and associated secret for authentication.
	*	It then hashes the user name and password and sends it to the server to authenticate with it
	*	After that it expects a hashed version of the username, password and secret catactinated back before trusting the server
	*	
	*	in - BufferedReader for getting information from the server
	*	stdIn - BufferedReader for getting information from the user
	*	out - PrintWriter for sending messages to the server
	*/
	private static boolean authenticateWServer( BufferedReader in, BufferedReader stdIn, PrintWriter out, Common commonLib ) {
		String username = "";
		String pass = "";
		String secret = "";

		try {

			MessageDigest hashFunc = MessageDigest.getInstance("SHA-256");
			System.out.println("Please enter authentication information");

			System.out.println("User Name: ");
			username = stdIn.readLine();

			System.out.println("Password: ");
			pass = stdIn.readLine();

			System.out.println("Secret: ");
			secret = stdIn.readLine();

			String encodedHashedUsername = Base64.getEncoder().encodeToString(hashFunc.digest(username.getBytes())); //get an encoded, hashed username
			String hashedUsername = new String(hashFunc.digest(username.getBytes()));
			//System.out.println( "Username" );
			//System.out.println( encodedHashedUsername ); // TODO remove these debug printlns
			String encodedHashedPass = Base64.getEncoder().encodeToString(hashFunc.digest(pass.getBytes())); //get an encoded, hashed password
			String hashedPass = new String(hashFunc.digest(pass.getBytes()));
			//System.out.println( "Password" );
			//System.out.println( encodedHashedPass ); // TODO remove these debug printlns
			String hashedSecret = new String(hashFunc.digest(secret.getBytes())); //got a hashed password, we don't need to encode it since it isn't being sent to the server
			//System.out.println( "Secret" );
			//System.out.println( encodedHashedSecret ); // TODO remove these debug printlns
			String encodedHashedSendStr = encodedHashedUsername + " " + encodedHashedPass;
			System.out.println(encodedHashedSendStr); // TODO remove this debug println
			
			//THIS WHOLE BLOCK COMMENTED OUT AS IT WAS USED TO SETUP THE STORED USERNAME AND PASSWORDS
			//Path path = FileSystems.getDefault().getPath("SecureFolder", "AuthenticatedUsers.txt");
			//FileWriter fWriter = new FileWriter( "SecureFolder/AuthenticatedUsers.txt", true );
			//BufferedWriter writer = new BufferedWriter(fWriter);
			//String hashedStr = hashedUsername + " " + hashedPass + " " + hashedSecret + "\n";
			//System.out.println(hashedStr);
			//System.out.println(hashedStr.length());
			//writer.write(hashedStr, 0, hashedStr.length());
			//writer.close();

			commonLib.sendMessage( encodedHashedSendStr, out, "" );

			String encodedHashedSecret = in.readLine();
			System.out.println("Read line back from server");
			String hashedSecretFrServer = new String(Base64.getDecoder().decode(encodedHashedSecret));

			if( !hashedSecret.equals(hashedSecretFrServer) ) {
				System.err.println( "Could not authenticate the server, please restart the client and try agian" );
				System.exit( 1 ); 
			}

			System.out.println("Authentication finished");

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
