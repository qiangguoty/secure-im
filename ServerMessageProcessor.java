/**
 * ServerMessageProcessor.java
 * 
 * @author  Jingdi Ren
 * @version 0.1
 * @since   Mar 22, 2014
 *
 */

//package IMServer;

//import IMUtil.*;
//import IMClient.*;

import java.io.*;
import java.net.*;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.concurrent.*;
import java.util.regex.*;

public class ServerMessageProcessor implements Runnable {
    public ServerMessageProcessor() {
    	this.aes = new AESCipher();
    	this.rsa = new RSACipher();    	
    	
        this.serverInfo = new ServerInfo();
        this.clientList = new ConcurrentHashMap<String, ClientSessionInfo>();
        this.socket = null;
        this.serverSocket = null;
    }

    public byte[] getClientList() {
        byte[] result = new byte[320];
        int i = 0;
        for (String name : this.clientList.keySet()) {
            byte[] slice = new byte[32];
            i++;
            System.arraycopy(slice, 0, name.getBytes(), 0, name.getBytes().length);
            System.arraycopy(result, i * 10, slice, 0, slice.length);
        }
        
        return result;
    }

    public AESCipher getAESCipher() {
    	return this.aes;
    }
    
    public RSACipher getRSACipher() {
    	return this.rsa;
    }
    
    public boolean isOnline(String username) {
        if (this.clientList.containsKey(username)) {
            return true;
        }
        return false;
    }
    
    // Handles request and connection
    @Override
    public void run() {
    	Thread clientThread = null;
    	
    	while (true) {
    		
    		try {
    			Socket clientSocket = this.serverSocket.accept();
    			if (clientSocket != null) {
    				System.out.println("Connection established ...");
    				clientThread = new Thread(new ServerProcessWorker(this, clientSocket));
    				clientThread.start();
    			}
    		} catch (IOException e) {
    		}
    		
    		
    	}
    }
    
    // get server socket
    public ServerSocket getServerSocket() {
        return this.serverSocket;
    }

    // set the server socket
    public void setServerSocket() {
        try {
        	this.serverSocket = new ServerSocket(this.getServer().getPort());
        	this.serverSocket.setSoTimeout(SOCKET_TIMEOUT);
        } catch (IOException e) {
        }
    }

    // user submit command to message list
    public synchronized boolean sumbitCommand(String command) {
        Pattern[] commandPatterns = this.getServer().getCommandsPatterns();
        Matcher commandMatcher = null;

        for (Pattern commandPattern : commandPatterns) {
            commandMatcher = commandPattern.matcher(command);
            if (commandMatcher.matches()) {
                //messageQueue.offer(new ServerTask(ServerTask.TASK_SEND, commandMatcher)); 
            	System.out.println("Command: " + command);
                return true;
            }
        }

        return false;
    }

    public void setDB(HashMap<String, String> db) {
    	this.masterKeyDB = db;
    }
    
    public HashMap<String, String> getDB() {
    	return this.masterKeyDB;
    }
    
    public ConcurrentHashMap<String, ClientSessionInfo> getClientMap() {
    	return this.clientList;
    }
    
	public byte[] getUserMasterKey(String username) {
        byte[] randomBytes = new byte[16];
        Random random = new Random();
        random.nextBytes(randomBytes);

        if (this.masterKeyDB.containsKey(username)) {
        	System.out.println("processor Find User " + username);
        	return this.masterKeyDB.get(username).getBytes();
        }
        
        return randomBytes;
	}
	
    public ServerInfo getServer() {
        return this.serverInfo;
    }
   
    public void loginUser(String clientUsername, InetAddress address, int port) {
    	clientList.put(clientUsername, new ClientSessionInfo(clientUsername, address, port));
    }
    // user list UserName ClientSeesionInfo
    private ConcurrentHashMap<String, ClientSessionInfo> clientList;

    // Client Info
    private ServerInfo serverInfo;

    // Session Client Info
    public LinkedBlockingQueue<ClientSessionInfo> sessionInfo;
  
    HashMap<String, String> masterKeyDB;
    
    // Cipher
    private AESCipher aes;
    private RSACipher rsa;
    
    // UDP Socket
    private Socket socket;
    private ServerSocket serverSocket;

    private final static int SOCKET_TIMEOUT = 1000;
}
