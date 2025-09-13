// Java vulnerability test file
import java.io.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class VulnerableApp {
    public static void main(String[] args) {
        try {
            // Command injection vulnerability
            if (args.length > 0) {
                Runtime.getRuntime().exec("ls " + args[0]);
            }
            
            // Weak hash function
            MessageDigest md = MessageDigest.getInstance("MD5");
            
            // Unsafe deserialization
            ObjectInputStream ois = new ObjectInputStream(new FileInputStream("data.ser"));
            Object obj = ois.readObject();
            ois.close();
            
            // Weak randomness
            double random = Math.random();
            System.out.println("Random: " + random);
            
        } catch (IOException | ClassNotFoundException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }
}