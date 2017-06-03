
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
import java.util.Arrays;
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
    String file = null;
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
                System.out.println("Client connected!");
                oo = new ObjectOutputStream(socket.getOutputStream());
                oi = new ObjectInputStream(socket.getInputStream());

                while (takingInput) {
                    Message response = (Message) oi.readObject();

                    //Disconect message response
                    if (response.getType() == MessageType.DISCONNECT) {
                        socket.close();
                        serverMode.close();
                    }

                    //Stop message response
                    if (response.getType() == MessageType.STOP) {
                        AckMessage abort = new AckMessage(-1);
                        oo.writeObject(abort);
                    }

                    //Start message response
                    if (response.getType() == MessageType.START) {
                        StartMessage startMessage = (StartMessage) response;
                        file = startMessage.getFile();
                        size = startMessage.getSize();
                        retrievedFile = new byte[(int) size];
                        chunkSize = startMessage.getChunkSize();
                        long tsize = size;
                        size = tsize/chunkSize;
                        

                        if (tsize == 0 || (tsize-size) > 0) {
                            size++;
                        }
                        byte[] encryptedKey = startMessage.getEncryptedKey();

                        privateKey = (PrivateKey) prois.readObject();

                        Cipher c = Cipher.getInstance("RSA");
                        c.init(Cipher.UNWRAP_MODE, privateKey);
                        key = c.unwrap(encryptedKey, "AES", Cipher.SECRET_KEY);

                        try {
                            AckMessage accept = new AckMessage(0);
                            oo.writeObject(accept);
                        } catch (ClassCastException e) {
                        }
                    }

                    //Chunk message response
                    if (response.getType() == MessageType.CHUNK) {
                        Chunk chunk = (Chunk) response;

                        if (chunk.getSeq() == expectedSeqNum) {

                            Cipher c = Cipher.getInstance("AES");
                            c.init(Cipher.DECRYPT_MODE, key);
                            byte[] decrypted = c.doFinal(chunk.getData());

                            CRC32 crc = new CRC32();
                            crc.reset();
                            crc.update(decrypted);

                            if (chunk.getCrc() == (int) crc.getValue()) {
                                System.out.println("Chunk received [" + (expectedSeqNum + 1) + "/" + size + "]");
                                expectedSeqNum++;
                                //retrievedFile[expectedSeqNum] = crc.getValue();
                                AckMessage next = new AckMessage(expectedSeqNum);
                                oo.writeObject(next);

                                if (size == expectedSeqNum) {
                                    System.out.println("Output Path: " + file);
                                    System.out.println("File transferred, shutting down...");
                                    takingInput = false;
                                    disconnected = true;
                                    socket.close();
                                    serverMode.close();
                                }
                            }

                        } else {
                            AckMessage abort = new AckMessage(expectedSeqNum);
                            System.out.println("ABORT");
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
            int pChunkSize = Integer.parseInt(specifiedChunkSize);
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(128);

            Key sessionKey = keyGen.generateKey();
            Cipher c = Cipher.getInstance("RSA");
            c.init(Cipher.WRAP_MODE, publicKey);
            byte[] toSend = c.wrap(sessionKey);
            
            FileInputStream fileInputStream = null;
            byte[] fileStore = null;
            byte[][] packagedFile = null;
            int tip = 0;
            
            try{
                File file1 = new File(filepath);
                System.out.println("Sending: " + filepath + "\tFile Size: "+file1.length());
                fileStore = new byte[(int) file1.length()];
                fileInputStream = new FileInputStream(file1);
                fileInputStream.read(fileStore);
            } catch (IOException e){
                e.printStackTrace();
            }
            
            tip = (int)(fileStore.length/pChunkSize);
            packagedFile = new byte[tip+1][];
            int remainder = (fileStore.length - (tip*pChunkSize));
            
            for(int i = 0; (i*pChunkSize) < fileStore.length; i++){
                if(tip == i){
                    packagedFile[i] = new byte[remainder];
                    packagedFile[i] = Arrays.copyOfRange(fileStore, (i*pChunkSize), (i*pChunkSize) + remainder - 1);
                }else if ( (((i*2)*pChunkSize)-1) == -1){
                    packagedFile[i] = new byte[pChunkSize];
                    packagedFile[i] = Arrays.copyOfRange(fileStore, (i*pChunkSize), 1);
                }else{
                    packagedFile[i] = new byte[pChunkSize];
                    packagedFile[i] = Arrays.copyOfRange(fileStore, (i*pChunkSize), (((i*2)*pChunkSize)-1));                
                }
            }
            
            StartMessage begin = new StartMessage(filepath, toSend, pChunkSize);

            //Initiate file transfer
            oo.writeObject(begin);
            
            //Chunk transfer loop
            for (int j = 0; j < (tip + 2); j++) {

                Message received = (Message) oi.readObject();

                if (received.getType() == MessageType.ACK) {
                    AckMessage ack = (AckMessage) received;
                    
                    if(ack.getSeq() == packagedFile.length){
                        System.out.println("All chunks sent!");
                    }else{
                        CRC32 crc = new CRC32();
                        crc.reset();
                        crc.update(packagedFile[ack.getSeq()]);

                        c = Cipher.getInstance("AES");
                        c.init(Cipher.ENCRYPT_MODE, sessionKey);
                        byte[] encryptedData = c.doFinal(packagedFile[ack.getSeq()]);
                    
                        Chunk sendThis = new Chunk(ack.getSeq(), encryptedData, (int)crc.getValue());
                        
                        try{
                            System.out.println("Chunk transferred [" + (sendThis.getSeq() + 1) + "/" + packagedFile.length + "]");
                            oo.writeObject(sendThis);
                        } catch(IOException e){
                            e.printStackTrace();
                        }
                }

                }
            }
            
        }
    }
}