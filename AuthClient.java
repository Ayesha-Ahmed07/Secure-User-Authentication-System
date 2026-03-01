import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.net.*;
import java.io.*;
import java.util.Base64;
import java.util.Scanner;
import java.util.Random;

public class AuthClient {
    private static final String SERVER_HOST = "localhost";
    private static final int SERVER_PORT = 65432;
    private static final String SECRET_KEY = "mysecretpassword";

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        boolean running = true;
        
        System.out.println("======Java Authentication Client=====");
        
        while (running) {
            System.out.println("\nAuthentication Client");
            System.out.println("1. Register");
            System.out.println("2. Login");
            System.out.println("3. Exit");
            System.out.print("Select option (1/2/3): ");
            
            int choice;
            try {
                choice = scanner.nextInt();
                scanner.nextLine(); // Consume newline
            } catch (Exception e) {
                System.out.println("Please enter a valid number");
                scanner.nextLine(); // Consume invalid input
                continue;
            }
            
            if (choice == 3) {
                running = false;
                System.out.println("Exiting client and sending shutdown signal to server...");
                try {
                    // Send exit notification to server
                    String response = sendExitSignal();
                    System.out.println("Server response: " + response);
                } catch (Exception e) {
                    System.err.println("Error sending exit signal: " + e.getMessage());
                }
                continue;
            }
            
            if (choice != 1 && choice != 2) {
                System.out.println("Invalid option. Please try again.");
                continue;
            }
            
            System.out.print("Username: ");
            String username = scanner.nextLine();
            
            System.out.print("Password: ");
            String password = scanner.nextLine();
            
            try {
                System.out.println("Attempting to connect to server...");
                String response = authenticate(choice == 1 ? "register" : "login", 
                                            username, password);
                System.out.println("Server response: " + response);
                
                // Display a more user-friendly message based on the response
                switch (response) {
                    case "REGISTRATION_SUCCESS":
                        System.out.println("Registration successful! You can now login.");
                        break;
                    case "LOGIN_SUCCESS":
                        System.out.println("Login successful! Welcome " + username);
                        break;
                    case "USER_EXISTS":
                        System.out.println("Username already exists. Please choose another.");
                        break;
                    case "WEAK_PASSWORD":
                        System.out.println("Password is too weak. It must be at least 8 characters.");
                        break;
                    case "USER_NOT_FOUND":
                        System.out.println("User not found. Please register first.");
                        break;
                    case "ACCOUNT_LOCKED":
                        System.out.println("Account locked due to too many failed attempts.");
                        break;
                    case "LOGIN_FAILED":
                        System.out.println("Incorrect password. Please try again.");
                        break;
                    default:
                        System.out.println("Received response: " + response);
                }
                
            } catch (Exception e) {
                System.err.println("Error: " + e.getMessage());
                e.printStackTrace();
            }
        }
        
        scanner.close();
    }

    public static String authenticate(String action, String username, String password) 
            throws Exception {
        try (Socket socket = new Socket(SERVER_HOST, SERVER_PORT);
             PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
             BufferedReader in = new BufferedReader(
                 new InputStreamReader(socket.getInputStream()))) {
            
            // Create JSON string manually with user agent info
            String request = String.format(
                "{\"action\":\"%s\",\"username\":\"%s\",\"password\":\"%s\",\"user_agent\":\"Java Client\"}",
                action, username, password);
            
            // Encrypt the request
            String encryptedRequest = encrypt(request);
            out.println(encryptedRequest);
            
            // Read and decrypt the response
            String encryptedResponse = in.readLine();
            if (encryptedResponse == null) {
                throw new IOException("No response received from server");
            }
            System.out.println("Raw response: " + encryptedResponse);
            return decrypt(encryptedResponse);
        }
    }
    
    public static String sendExitSignal() throws Exception {
        try (Socket socket = new Socket(SERVER_HOST, SERVER_PORT);
             PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
             BufferedReader in = new BufferedReader(
                 new InputStreamReader(socket.getInputStream()))) {
            
            // Create exit request with user agent info
            String request = "{\"action\":\"exit\",\"username\":\"system\",\"password\":\"exit\",\"user_agent\":\"Java Client Shutdown\"}";
            
            // Encrypt the request
            String encryptedRequest = encrypt(request);
            out.println(encryptedRequest);
            
            // Read and decrypt the response
            String encryptedResponse = in.readLine();
            if (encryptedResponse == null) {
                return "Server shutdown initiated";
            }
            return decrypt(encryptedResponse);
        }
    }

    private static String encrypt(String plainText) throws Exception {
        // Generate random IV
        byte[] iv = new byte[16];
        new Random().nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        
        // Create key
        SecretKeySpec secretKey = new SecretKeySpec(SECRET_KEY.getBytes(), "AES");

        // Encrypt
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes("UTF-8"));
        
        // Create JSON response with IV and ciphertext
        String jsonResponse = String.format(
            "{\"iv\":\"%s\",\"ciphertext\":\"%s\"}",
            Base64.getEncoder().encodeToString(iv),
            Base64.getEncoder().encodeToString(encryptedBytes)
        );
        
        return jsonResponse;
    }

    private static String decrypt(String encryptedData) throws Exception {
        try {
            // Parse JSON manually with better handling of whitespace and quotes
            String json = encryptedData.trim(); // Trim any leading/trailing whitespace
            
            // Find the iv value
            int ivStart = json.indexOf("\"iv\"");
            if (ivStart == -1) throw new Exception("IV key not found in response");
            
            ivStart = json.indexOf(":", ivStart) + 1;
            ivStart = json.indexOf("\"", ivStart) + 1;
            int ivEnd = json.indexOf("\"", ivStart);
            String ivBase64 = json.substring(ivStart, ivEnd);
            
            // Find the ciphertext value
            int ctStart = json.indexOf("\"ciphertext\"");
            if (ctStart == -1) throw new Exception("Ciphertext key not found in response");
            
            ctStart = json.indexOf(":", ctStart) + 1;
            ctStart = json.indexOf("\"", ctStart) + 1;
            int ctEnd = json.indexOf("\"", ctStart);
            String ciphertextBase64 = json.substring(ctStart, ctEnd);
            
            // Get IV and ciphertext
            byte[] iv = Base64.getDecoder().decode(ivBase64);
            byte[] ciphertext = Base64.getDecoder().decode(ciphertextBase64);
            
            // Set up key and IV
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            SecretKeySpec secretKey = new SecretKeySpec(SECRET_KEY.getBytes(), "AES");
    
            // Decrypt
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
            
            return new String(cipher.doFinal(ciphertext), "UTF-8");
        } catch (Exception e) {
            throw new Exception("Failed to decrypt: " + e.getMessage() + ", Data: " + encryptedData);
        }
    }
}