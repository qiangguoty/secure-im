/**
 * ServerConsole.java
 * 
 * @author  Jingdi Ren
 * @version 0.1
 * @since   Mar 22, 2014
 *
 */
//package IMServer;

import java.io.*;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.regex.*;

public class ServerConsole {
    public ServerConsole() {
    	this.console = System.console();
        // the creator of all the process worker
        this.messageProcessor = new ServerMessageProcessor();
    }	
    
    public static void main(String[] args) {
        ServerConsole cs = new ServerConsole();
        boolean status = false;

        /* read the configuration file */
        status = cs.config();
        if (status == false) {
            System.out.println("ServerConsole: failed to config");
            System.exit(-1);
            return;
        }

        /* log in */
        status = cs.login();
        if (status == false) {
            System.out.println("ServerConsole: failed to login");
            System.exit(-1);
            return;
        }

        /* start the console */
        status = cs.startConsole();
        if (status == false) {
            System.out.println("ServerConsole: failed to start the console");
            System.exit(-1);
        }
    }
    
    public boolean config() {
        boolean isConfigFileExists = true;
        try {
            readConfigFile();
        } catch (FileNotFoundException e) {
            isConfigFileExists = false;
        }

        if (isConfigFileExists == true) {
            parseConfigFile();
            return true;
        }

        return false;
    }
    
    public boolean login() {
        // Set up the socket
    	boolean checkStatus = false;
        this.messageProcessor.setServerSocket();
      
        System.out.println("Secure Instant Message Server");
        char[] password = console.readPassword("Please enter the password:");
        //System.out.println(Arrays.equals(new String(password).getBytes(), new String("12345").getBytes()));
        this.messageProcessor.getAESCipher().generateKey(new String(password).getBytes());
  
        try {
        	//initDB();
        	this.messageProcessor.setDB(ServerDBHelper.readDB(this.messageProcessor.getAESCipher()));
        	if (this.messageProcessor.getDB() == null) {
        		return false;
        	}
        } catch (Exception e) {
            e.printStackTrace();
        	return false;
        }
       
        System.out.println("Login to the system successfully...");
        
        return true;
    }

    public void initDB() throws IOException, NoSuchAlgorithmException {
        ServerDBHelper.resetDB(this.messageProcessor.getAESCipher());
    }

    public boolean validateUsername(String username) {
        boolean result = false;

        try {
            if (this.messageProcessor.isOnline(username)) {
                // logged in before
                throw new Exception("logged in before");
            }
            else {
                // read server DB
                HashMap<String, String> db = ServerDBHelper.readDB(this.messageProcessor.getAESCipher());
                if (db.containsKey(username)) {
                    result = true;
                }
            }

        } catch (Exception e) {
            // e.printStackTrace();
            result = false;
        }

        return result;
    }


    private void readConfigFile() throws FileNotFoundException {
        InputStream is = new FileInputStream(CONFIG_FILE_NAME);
        Scanner scan = new Scanner(is);
        
        Pattern hpattern = Pattern.compile("<(.*)>");
        Pattern lpattern = Pattern.compile("(.*)=(.*)");
        Matcher m = null;
        String itemName = null;
        HashMap<String,String> configureItem = null;
        
        configurationTable = new HashMap<String, HashMap<String,String>>();
        while (scan.hasNext()) {

            /* find the next items */
            while ((scan.hasNext()) && !(scan.hasNext(hpattern))) {
                scan.nextLine();
            }
           
            /* parse the item */
            if (scan.hasNext()) {
                /* find a new item */
                m = hpattern.matcher(scan.nextLine());
                if (m.matches()) {
                    itemName = m.group(1);
                    configureItem = new HashMap<String,String>();
                }

                /* insert the item */
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

    private void parseConfigFile() {
        HashMap<String, String> item = null;
        String username = null;
        String password = null;

        for (String s : configurationTable.keySet()) {
            item = configurationTable.get(s);
            if (s.compareTo("server") == 0) {
                for (String i : item.keySet()) {
                    if (i.compareTo("port") == 0) {
                        this.messageProcessor.getServer().setPort(Integer.parseInt(item.get(i)));
                    }
                }
            }
            else if (s.compareTo("user") == 0) {
                for (String i : item.keySet()) {
                    if (i.compareTo("name") == 0) {
                    	username = i;
                    }
                    else if (i.compareTo("passwd") == 0) {
                    	password = i;
                    	
                    }
                }
            }
        }
    }

    private void printMap() {
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

    /* console */
    public boolean startConsole() {
        String cmd = null;
        boolean isError = false;
        boolean status = false;

        Thread processThread = new Thread(messageProcessor);

        processThread.start();

        while (true) {
            try {
                cmd = console.readLine();            
            }
            catch (NullPointerException e) {
                System.out.println("ServerConsole: failed to open console");
                isError = true;
            }
            finally {
                console.flush();
            }

            if (cmd.compareTo("exit") == 0) {
                break;
            }
            if ((isError) || (cmd.compareTo("exit") == 0)) {
                break;
            }
            
            status = this.messageProcessor.sumbitCommand(cmd);
            if (status == false) {
                System.out.println("command is invalid");
            }
        }

        if (isError) {
            return false;
        }

        try {
            processThread.join();
        } catch (InterruptedException e) {
            System.out.println("failed to join");
        }

        return true;
    }
    
    private static HashMap<String,HashMap<String,String>> configurationTable;
    private ServerMessageProcessor messageProcessor;

    private static Console console;

    private final static String CONFIG_FILE_NAME = "server.cfg";
}
