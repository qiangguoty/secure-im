/*
 * ServerInfo.java
 * 
 * @author  Jingdi Ren
 * @since   Mar 23, 2014
 * @notes
 *
 */
//package IMServer;

import java.net.*;
import java.util.regex.Pattern;

public class ServerInfo {
    public ServerInfo() {
    	try {
    		this.serverName = "SERVER".getBytes();
    		this.IPAddress = InetAddress.getLocalHost();
    	} catch (UnknownHostException e) {
    		this.IPAddress = null;
    	}
    	
        this.port = 0;
    }

    public ServerInfo(InetAddress IPAddress, int port) {
        this.IPAddress = IPAddress;
        this.port = port;
    }

    public InetAddress getIPAddress() {
        return this.IPAddress;
    }

    public int getPort() {
        return this.port;
    }

    public void setPort(int port) {
    	this.port = port;
    }

    public Pattern[] getCommandsPatterns() {
        return commandPatterns;
    }
    
    public byte[] getServerName() {
    	return this.serverName;
    }
    
    private final static Pattern[] commandPatterns = { Pattern.compile("list"), 
                                                       Pattern.compile("history"),
                                                       Pattern.compile("info"),
                                                       Pattern.compile("add (.?) (.?)"),
                                                       Pattern.compile("delete (.?)") };

    private byte[] serverName;
	private InetAddress IPAddress;
	private int port;
}
