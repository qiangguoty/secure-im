/**
 * ClientSendWorker.java
 * 
 * @author  Jingdi Ren
 * @version 0.1
 * @since   Mar 22, 2014
 *
 */
//package IMClient;

//import IMUtil.*;

import java.io.*;
import java.net.*;

public class ClientSendWorker implements Runnable {
    public ClientSendWorker(ClientMessageProcessor processor) {
        this.messageProcessor = processor;
        this.isRunning = true;
    }

    // get the message from sendQueue and build the DatagramPacket
    @Override
    public void run() {
        DatagramPacket packet = null; 
        EncryptedMessage message = null;
        byte[] sendBuffer = null;

        while (this.isRunning) {
            if (!messageProcessor.getSendList().isEmpty()) {
                message = messageProcessor.getSendList().poll();
                System.out.println("Send " + message);
                sendBuffer = new byte[MAX_SEND_BUFFER];
                try {
                    messageProcessor.getServerOutputStream().write(message.getBytes());
                } catch (IOException e) {
                    System.out.println("ClientSendWorker fail to send packet");
                }
            }
            else {
                try {
                    Thread.sleep(100);
                } catch (InterruptedException e) {
                    this.isRunning = false;
                }
            }
        }
    }

    // pause the polling while loop
    public void pause() {
        this.isRunning = false;
    }

    private boolean isRunning;

    private ClientMessageProcessor messageProcessor;
    
    private static final int MAX_SEND_BUFFER = 1024;
}
