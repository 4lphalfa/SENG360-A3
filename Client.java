import javax.crypto.*;
import java.io.*;
import java.net.*;

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
					boolean authenticated = authenticateWServer( in, out );

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

	private static boolean authenticateWServer( BufferedReader in, PrintWriter out ) {

		return true;
	}
}
