
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Scanner;
import java.util.zip.CRC32;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;



/**
 *
 * @author Jorge
 */
public class FileTransfer {
public static void main(String[] args) throws Exception {
    boolean disconnected = false;
    boolean takingInput = true;
    byte[] retrievedFile;
    String file;
    long size = 0;
    int chunkSize;
    Key key = null;
    Key clientKey = null;
    int expectedSeqNum = 0;
    ObjectOutputStream oo;
    ObjectInputStream oi;
    
    
        //Keygen
        if (args.length > 0 && args[0].equals("makekeys")) {
            try {
                KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
                gen.initialize(4096);
                KeyPair keyPair = gen.genKeyPair();
                PrivateKey privateKey = keyPair.getPrivate();
                PublicKey publicKey = keyPair.getPublic();
                try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(new File("public.bin")))) {
                    oos.writeObject(publicKey);
                }
                try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(new File("private.bin")))) {
                    oos.writeObject(privateKey);
                }
                System.out.println("Keys genned.");
            } catch (NoSuchAlgorithmException | IOException e) {
                e.printStackTrace(System.err);
            }
        }
        
        //Server mode
        if (args.length > 0 && args[0].equals("server")) {
        String privateKeyFile = args[1];
        int port = Integer.parseInt(args[2]);
        
        PrivateKey privateKey;
        ObjectInputStream prois = new ObjectInputStream(new FileInputStream(privateKeyFile));        

        while (!disconnected) {

            try (ServerSocket serverMode = new ServerSocket(port)) {
                Socket socket = serverMode.accept();
                oo = new ObjectOutputStream(socket.getOutputStream());
                oi = new ObjectInputStream(socket.getInputStream());
                
                while(takingInput){
                Message response = (Message)oi.readObject();
                
                //Disconect message response
                if(response.getType() == MessageType.DISCONNECT){
                socket.close();
                serverMode.close();
                }
                
                //Stop message response
                if(response.getType() == MessageType.STOP){
                    AckMessage abort = new AckMessage(-1);
                    oo.writeObject(abort);
                }
                
                //Start message response
                if(response.getType() == MessageType.START){
                //StartMessage response = (StartMessage)oi.readObject();
                StartMessage startMessage = (StartMessage)response;
                file = startMessage.getFile();
                size = startMessage.getSize();
                retrievedFile = new byte[(int)size];
                chunkSize = startMessage.getChunkSize();
                byte[] encryptedKey = startMessage.getEncryptedKey();
                
                    privateKey = (PrivateKey) prois.readObject();               
                
                Cipher c = Cipher.getInstance("AES");
                c.init(Cipher.UNWRAP_MODE, privateKey);
                key = (Key) c.unwrap(encryptedKey, "AES", Cipher.PUBLIC_KEY);
                
                    try{
                        AckMessage accept = new AckMessage(0);
                        oo.writeObject(accept);
                    }catch (ClassCastException e){}
                }
                
                //Chunk message response
                if(response.getType() == MessageType.CHUNK){
                    Chunk chunk = (Chunk) response;
                    if(chunk.getSeq() == expectedSeqNum){
                        
                        Cipher c = Cipher.getInstance("AES");
                        c.init(Cipher.DECRYPT_MODE, key);
                        
                        CRC32 crc = new CRC32();
                        crc.update(chunk.getData(), 0, chunk.getData().length);
                        crc.getValue();
                        if(chunk.getCrc() == crc.getValue()){
                            System.out.println("Chunk received [" + expectedSeqNum + "/" + size + "]");
                            expectedSeqNum++;
                            //retrievedFile[expectedSeqNum] = crc.getValue();
                            AckMessage next = new AckMessage(expectedSeqNum);
                            oo.writeObject(next);
                            if(size == expectedSeqNum){
                                System.out.println("File transferred, shutting down...");
                                takingInput = false;
                                disconnected = true;
                                socket.close();
                                serverMode.close();
                            }
                        }
                        
                    }else{
                        AckMessage abort = new AckMessage(expectedSeqNum);
                        oo.writeObject(abort);
                    }
                }
            }
            }
        }
        }
        
        //Client mode
        if(args.length > 0 && args[0].equals("client")){
            String publicKeyFile = args[1];
            String host = args[2];
            String port = args[3];
            
            Socket cSocket = new Socket(host, Integer.parseInt(port));
            
        ObjectInputStream puois = new ObjectInputStream(new FileInputStream(publicKeyFile));
            
            PublicKey publicKey = (PublicKey) puois.readObject();
            oo = new ObjectOutputStream(cSocket.getOutputStream());
            oi = new ObjectInputStream(cSocket.getInputStream());
                
            Scanner keyboardIn = new Scanner(System.in);
            System.out.print("Enter filepath: ");
            String filepath = keyboardIn.nextLine();
            System.out.print("Enter chunk size: ");
            String specifiedChunkSize = keyboardIn.nextLine();
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(128);
            SecretKey sessionKey = keyGen.generateKey();
            Cipher c = Cipher.getInstance("AES");
            c.init(Cipher.WRAP_MODE, publicKey);
            byte[] toSend = c.wrap(sessionKey);
            
            StartMessage begin = new StartMessage(filepath, toSend, Integer.parseInt(specifiedChunkSize));
            
            oo.writeObject(begin);
            Message received = (Message)oi.readObject();
            
            if(received.getType() == MessageType.ACK){
                System.out.println("SUCCESS");
            }
            
        }
    }
}
