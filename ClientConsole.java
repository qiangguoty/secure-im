/**
 * ClientConsole.java
 * 
 * @author  Jingdi Ren
 * @version 0.1
 * @since   Mar 22, 2014
 *
 */

import java.io.*;
import java.io.*;
import java.net.*;
import java.util.*;
import java.util.regex.*;

public class ClientConsole {

    public ClientConsole() {
        this.console = System.console();

        this.messageProcessor = new ClientMessageProcessor();
        this.sendWorker = new ClientSendWorker(this.messageProcessor);
        this.receiveWorker = new ClientReceiveWorker(this.messageProcessor);
        this.messager = new ClientMessager(this.messageProcessor);
    }

    public static void main(String[] args) {
        ClientConsole cs = new ClientConsole();
        boolean status = false;

        /* read the configuration file */
        status = cs.config();
        if (status == false) {
            System.out.println("ClientConsole: failed to config");
            return;
        }

        /* log in */
        status = cs.login();
        if (status == false) {
            System.out.println("ClientConsole: failed to login");
            return;
        }

        // generate the RSA key pair and store it into ClientInfo
        /* start the console */
        status = cs.startConsole();
        if (status == false) {
            System.out.println("ClientConsole: failed to start the console");
        }
    }

    public boolean config() {
        boolean isConfigFileExists = true;
        try {
            this.readConfigFile();
        } catch (FileNotFoundException e) {
            isConfigFileExists = false;
        }

        if (isConfigFileExists == true) {
            this.parseConfigFile();
            return true;
        }

        return false;
    }

    /* login the user
     * returns 0 if succeed
     * returns -1 if the user or password doesn't match
     */
    public boolean login() {
        /* initialize the login parameter */
    	EncryptedMessage message = null;
    	EncryptedMessage responseMessage = null;
        String buffer = null;
        int attemptTime = 0;
        byte[] bytes = new byte[4096];
        
        System.out.println("Secure Instant Message System");

        // Set up the socket to the server
        if (this.messageProcessor.setServerSocket() == false) {
        	System.out.println("ClientConsole: failed to connect to the server");
        	return false;
        }
        
        do {
            buffer = console.readLine("Enter user name:");
            
            this.messageProcessor.setClientName(buffer);
            buffer = new String(console.readPassword("Enter your password:"));
            this.messageProcessor.setClientPassword(buffer);
            this.messageProcessor.getAESCipher().generateKey(buffer.getBytes());
            message = this.messageProcessor.parseLoginAttemptMessage();
            try {
				this.messageProcessor.getServerOutputStream().write(message.getBytes());
				this.messageProcessor.getServerInputStream().read(bytes);
			} catch (IOException e) {
				e.printStackTrace();
			}
            responseMessage = new EncryptedMessage(this.messageProcessor.getServerIPAddress(),
            									   this.messageProcessor.getServerPort(),
            									   bytes);

            this.messageProcessor.isLoginAttemptSucceed = true;
            
            if (this.messageProcessor.isLoginAttemptSucceed == true) {
            	break;
            }
            
            attemptTime++;
            if (attemptTime >= CONSOLE_MAX_LOGIN_TIME) {
            	return false;
            }
            
        } while (true);
       
        return true;
    }
    
    /* console */
    public boolean startConsole() {
        String commandString = null;
        boolean isError = false;

        if (this.messageProcessor.setClientSocket() == false) {
        	return false;
        }
        
        Thread send = new Thread(this.sendWorker);
        Thread receive = new Thread(this.receiveWorker);
        Thread messagerThread = new Thread(this.messager);
        send.start();
        receive.start();
        messagerThread.start();

        while (true) {
            try {
                commandString = console.readLine();            
            }
            catch (NullPointerException e) {
                System.out.println("ClientConsole: failed to open console");
                isError = true;
            }
            finally {
                console.flush();
            }
            
            if (isError) {
                break;
            }
           
            if (commandString != null)  {
            	if (commandString.compareTo("help") == 0) {
            		displayCommand();
            	}
            	else {
            		sumbitCommand(commandString);
            		if (commandString.compareTo("exit") == 0) {
            			// TBD: wait until "exit" command is sent
            			try {
            				Thread.sleep(1000);
            			} catch (InterruptedException e) {
            				
            			}
            			break;
            		}
            	}
            }
        }

        try {
        	sendWorker.pause();
            receiveWorker.pause();
            this.messager.pause();
            
            send.join();
            receive.join();
            messagerThread.join();
        } catch (InterruptedException e) {
            System.out.println("failed to join");
        }

        return (isError == false);
    }
    
    private void readConfigFile() throws FileNotFoundException {
        InputStream is = new FileInputStream(CONFIG_FILE_NAME);
        Scanner scan = new Scanner(is);
        // Mar 22 6:03PM
        // ClientConsole.java:21: illegal escape character
        //         Pattern hpattern = Pattern.compile("\[[a-z]\]");
        Pattern hpattern = Pattern.compile("<(.*)>");
        Pattern lpattern = Pattern.compile("(.*)=(.*)");
        Matcher m = null;
        String itemName = null;
        HashMap<String,String> configureItem = null;

        configurationTable = new HashMap<String, HashMap<String,String>>();

        while (scan.hasNext()) {
            /* find the next <item> */
            while ((scan.hasNext()) && !(scan.hasNext(hpattern))) {
                scan.nextLine();
            }

            /* parse the <item> */
            if (scan.hasNext()) {
                /* find the <title> */
                m = hpattern.matcher(scan.nextLine());
                if (m.matches()) {
                    itemName = m.group(1);
                    configureItem = new HashMap<String,String>();
                }

                /* find the element */
                while (scan.hasNext() && (!scan.hasNext(hpattern))) {
                    m = lpattern.matcher(scan.nextLine());
                    if (m.matches()) {
                        configureItem.put(m.group(1), m.group(2));
                    }
                }

                if (itemName != null) {
                    configurationTable.put(itemName, configureItem);
                }
            }
        }
    }

    // print the map
    public void printMap() {
        HashMap<String, String> item = null;
        // symbol  : method getKeys()
        // location: class java.util.HashMap<java.lang.String,java.util.HashMap<java.lang.String,java.lang.String>>
        //         for (String s : configurationTable.getKeys())
        for (String s : configurationTable.keySet()) {
            item = configurationTable.get(s);
            System.out.println("<" + s + ">");
            for (String i : item.keySet()) {
                System.out.println(i + " : " + item.get(i));
            }
        }
    }

    private void parseConfigFile() {
        HashMap<String, String> item = null;

        for (String s : configurationTable.keySet()) {
            item = configurationTable.get(s);
            if (s.compareTo("server") == 0) {
                for (String i : item.keySet()) {
                    if (i.compareTo("address") == 0) {
                    	try {
                    		this.messageProcessor.setServerIPAddress(InetAddress.getByName(item.get(i)));
                    	} catch (UnknownHostException e) { }
                    }
                    else if (i.compareTo("port") == 0) {
                        this.messageProcessor.setServerPort(Integer.parseInt(item.get(i)));
                    }
                }
            }
            else if (s.compareTo("user") == 0) {
                // TBD: this is used for automatic test, will be deleted in the future
                for (String i : item.keySet()) {
                    if (i.compareTo("id") == 0) {
                        this.messageProcessor.getClient().setName(item.get(i));
                    }
                    else if (i.compareTo("port") == 0) {
                        this.messageProcessor.getClient().setPort(Integer.parseInt(item.get(i)));
                    }
                }
            }
        }
    }

    // Display all commands for client
    public void displayCommand() {
        Pattern[] commandPatterns = messageProcessor.getClient().getCommandsPatterns();

        System.out.println("Display all commands");
        for (Pattern commandPattern : commandPatterns) {
        	System.out.println(commandPattern);
        }
    }
   
    // Check the command and add it into messageQueue
    public void sumbitCommand(String command) {
        Pattern[] commandPatterns = messageProcessor.getClient().getCommandsPatterns();
        Matcher commandMatcher = null;
        byte taskIndex = 0;

        for (Pattern commandPattern : commandPatterns) {
            commandMatcher = commandPattern.matcher(command);
            taskIndex++;
            if (commandMatcher.matches()) {
            	messageProcessor.offerCommand(taskIndex, commandMatcher);
            }
        }
    }
    
    private ClientMessageProcessor messageProcessor;
    private ClientSendWorker sendWorker;
    private ClientReceiveWorker receiveWorker;
    private ClientMessager messager;

    private HashMap<String,HashMap<String,String>> configurationTable;

    private Console console;

    private final static String CONFIG_FILE_NAME = "client.cfg";
    private final static int CONSOLE_MAX_LOGIN_TIME = 5;
}
