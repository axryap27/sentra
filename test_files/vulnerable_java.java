// Java vulnerability test file
import java.io.*;
import java.security.MessageDigest;

public class VulnerableApp {
    public static void main(String[] args) {
        // Command injection vulnerability
        Runtime.getRuntime().exec("ls " + args[0]);
        
        // Weak hash function
        MessageDigest md = MessageDigest.getInstance("MD5");
        
        // Unsafe deserialization
        ObjectInputStream ois = new ObjectInputStream(new FileInputStream("data.ser"));
        Object obj = ois.readObject();
        
        // Weak randomness
        double random = Math.random();
    }
}