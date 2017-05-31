
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
import javax.crypto.Cipher;



/**
 *
 * @author Jorge
 */
public class FileTransfer {
public static void main(String[] args) throws Exception {
    boolean disconnected = false;
    
        //Keygen
        //if (args.length > 0 && args[0].equals("makekeys")) {
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
            } catch (NoSuchAlgorithmException | IOException e) {
                e.printStackTrace(System.err);
            }
        //}
        
        //Server mode
        if (args.length > 0 && args[0].equals("server")) {
        String privateKeyFile = args[1];
        int port = Integer.parseInt(args[2]);
        PrivateKey privateKey;
        ObjectInputStream prois = new ObjectInputStream(new FileInputStream("private.bin"));        

        while (!disconnected) {
            try (ServerSocket serverMode = new ServerSocket(port)) {
                Socket socket = serverMode.accept();
                ObjectOutputStream oo = new ObjectOutputStream(socket.getOutputStream());
                ObjectInputStream oi = new ObjectInputStream(socket.getInputStream());
                
                try{
                DisconnectMessage response = (DisconnectMessage)oi.readObject();
                socket.close();
                serverMode.close();
                } catch(ClassCastException e){
                    System.out.println("DM "+e);
                }
                
                try{
                StartMessage response = (StartMessage)oi.readObject();
                String file = response.getFile();
                long size = response.getSize();
                int chunkSize = response.getChunkSize();
                byte[] encryptedKey = response.getEncryptedKey();
                
                    privateKey = (PrivateKey) prois.readObject();               
                
                Cipher c = Cipher.getInstance("AES");
                c.init(Cipher.UNWRAP_MODE, privateKey);
                Key key = (Key) c.unwrap(encryptedKey, "AES", ?);
                
                    try{
                        AckMessage accept = new AckMessage(0);
                        oo.writeObject(accept);
                    }catch (ClassCastException e){}
                    
                } catch(ClassCastException e){
                    System.out.println("StaM "+e);
                }
            }
        }
        }
        
        //Client mode
        if(args.length > 0 && args[0].equals("client")){
            String publicKeyFile = args[1];
            String host = args[2];
            String port = args[3];
        }
    }
}
