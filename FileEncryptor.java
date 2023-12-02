import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.awt.GridLayout;
import java.awt.BorderLayout;

public class FileEncryptor {
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/ECB/PKCS5Padding";

    private JTextField keyTextField;
    private JTextField filePathTextField;
    private static JTextArea logTextArea;

    public FileEncryptor() {
        JFrame frame = new JFrame("File Encryptor/Decryptor");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(400, 300);

        JPanel panel = new JPanel();
        panel.setLayout(new GridLayout(5, 3));

        keyTextField = new JTextField();
        filePathTextField = new JTextField();
        logTextArea = new JTextArea();

        JButton chooseFileButton = new JButton("Choose File/Directory");
        chooseFileButton.addActionListener(e -> chooseFileOrDirectory());

        JButton encryptButton = new JButton("Encrypt");
        encryptButton.addActionListener(e -> encryptFile());

        JButton decryptButton = new JButton("Decrypt");
        decryptButton.addActionListener(e -> decryptFile());

        JButton decryptDirectoryButton = new JButton("Decrypt Directory");
        decryptDirectoryButton.addActionListener(e -> decryptDirectory());

        JButton encryptDirectoryButton = new JButton("Encrypt Directory");
        encryptDirectoryButton.addActionListener(e -> encryptDirectory());

        panel.add(new JLabel("Key:"));
        panel.add(keyTextField);
        panel.add(new JLabel("File Path:"));
        panel.add(filePathTextField);
        panel.add(chooseFileButton);
        panel.add(new JLabel());
        panel.add(encryptButton);
        panel.add(encryptDirectoryButton);
        panel.add(decryptButton);
        panel.add(decryptDirectoryButton);

        JScrollPane logScrollPane = new JScrollPane(logTextArea);

        frame.getContentPane().setLayout(new BorderLayout());
        frame.getContentPane().add(panel, BorderLayout.NORTH);
        frame.getContentPane().add(logScrollPane, BorderLayout.CENTER);

        frame.setVisible(true);
    }

    private void chooseFileOrDirectory() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setFileSelectionMode(JFileChooser.FILES_AND_DIRECTORIES);
    
        int result = fileChooser.showOpenDialog(null);
        if (result == JFileChooser.APPROVE_OPTION) {
            File selectedFileOrDirectory = fileChooser.getSelectedFile();
            filePathTextField.setText(selectedFileOrDirectory.getAbsolutePath());
        }
    }

    private void encryptFile() {
        String key = keyTextField.getText();
        String filePath = filePathTextField.getText();
    
        if (!key.isEmpty() && !filePath.isEmpty()) {
            File inputFile = new File(filePath);
    
            try {
                if (inputFile.exists()) {
                    if (inputFile.isDirectory()) {
                        // Handle encryption of a directory
                        log("Encrypting directory: " + filePath);
                        encryptDirectory(key, inputFile);
                        log("Directory encrypted successfully.");
                    } else {
                        // Handle encryption of a single file
                        log("Encrypting file: " + filePath);
                        encrypt(key, inputFile);
                        log("File encrypted successfully.");
                    }
                } else {
                    log("Error encrypting file or directory: Does not exist.");
                }
            } catch (Exception ex) {
                log("Error encrypting file or directory: " + ex.getMessage());
            }
        } else {
            log("Please enter a key and choose a file or directory.");
        }
    }

    // Add a new method to handle directory encryption
    private void encryptDirectory() {
        String key = keyTextField.getText();
        String directoryPath = filePathTextField.getText();

        if (!key.isEmpty() && !directoryPath.isEmpty()) {
            File inputDirectory = new File(directoryPath);

            if (inputDirectory.exists() && inputDirectory.isDirectory()) {
                log("Encrypting directory: " + directoryPath);
                encryptDirectory(key, inputDirectory);
                log("Directory encrypted successfully.");
            } else {
                log("Error encrypting directory: Directory does not exist or is not a directory.");
            }
        } else {
            log("Please enter a key and choose a directory.");
        }
    }

    // Modify the encryptDirectory method to handle both files and subdirectories
    private void encryptDirectory(String key, File inputDirectory) {
        File[] files = inputDirectory.listFiles();

        if (files != null) {
            for (File file : files) {
                if (file.isDirectory()) {
                    // If it's a subdirectory, recursively encrypt it
                    encryptDirectory(key, file);
                } else {
                    // If it's a file, encrypt it
                    try {
                        encrypt(key, file);
                        log("File encrypted successfully: " + file.getAbsolutePath());
                    } catch (Exception ex) {
                        log("Error encrypting file: " + file.getAbsolutePath() + " - " + ex.getMessage());
                    }
                }
            }
        }
    }

    private void decryptDirectory() {
        String key = keyTextField.getText();
        String directoryPath = filePathTextField.getText();

        if (!key.isEmpty() && !directoryPath.isEmpty()) {
            File inputDirectory = new File(directoryPath);

            if (inputDirectory.exists() && inputDirectory.isDirectory()) {
                log("Decrypting directory: " + directoryPath);
                decryptDirectory(key, inputDirectory);
                log("Directory decrypted successfully.");
            } else {
                log("Error decrypting directory: Directory does not exist or is not a directory.");
            }
        } else {
            log("Please enter a key and choose a directory.");
        }
    }

    private void decryptDirectory(String key, File inputDirectory) {
        File[] files = inputDirectory.listFiles();

        if (files != null) {
            for (File file : files) {
                if (file.isDirectory()) {
                    // If it's a subdirectory, recursively decrypt it
                    decryptDirectory(key, file);
                } else {
                    // If it's a file, decrypt it
                    try {
                        decrypt(key, file);
                        log("File decrypted successfully: " + file.getAbsolutePath());
                    } catch (Exception ex) {
                        log("Error decrypting file: " + file.getAbsolutePath() + " - " + ex.getMessage());
                    }
                }
            }
        }
    }

    private void decryptFile() {
        String key = keyTextField.getText();
        String filePath = filePathTextField.getText();

        if (!key.isEmpty() && !filePath.isEmpty()) {
            File inputFile = new File(filePath);

            try {
                decrypt(key, inputFile);
                log("File decrypted successfully.");
            } catch (Exception ex) {
                log("Error decrypting file: " + ex.getMessage());
            }
        } else {
            log("Please enter a key and choose a file.");
        }
    }

    private static void log(String message) {
        logTextArea.append(message + "\n");
    }

    public static void encrypt(String key, File inputFile)
            throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException {
        doCrypto(Cipher.ENCRYPT_MODE, key, inputFile);
    }

    public static void decrypt(String key, File inputFile)
            throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException {
        doCrypto(Cipher.DECRYPT_MODE, key, inputFile);
    }

    private static void doCrypto(int cipherMode, String key, File inputFile) {
        // Ensure key length is valid
        if (key.length() != 16 && key.length() != 24 && key.length() != 32) {
            log("Invalid key length. Key must be 16, 24, or 32 bytes long.");
            return;
        }

        Key secretKey = new SecretKeySpec(key.getBytes(), ALGORITHM);
        Cipher cipher;
        try {
            cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(cipherMode, secretKey);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e) {
            e.printStackTrace();
            log("Error initializing Cipher: " + e.getMessage());
            return;
        }

        try (RandomAccessFile randomAccessFile = new RandomAccessFile(inputFile, "rw");
                FileChannel fileChannel = randomAccessFile.getChannel()) {

            // Use a direct byte buffer for efficient reading and writing
            ByteBuffer buffer = ByteBuffer.allocateDirect(8192);
            int bytesRead;
            while ((bytesRead = fileChannel.read(buffer)) > 0) {
                buffer.flip(); // Flip the buffer to prepare for reading
                byte[] chunk = new byte[bytesRead];
                buffer.get(chunk); // Read data from the buffer
                try {
                    byte[] processedBytes = cipher.doFinal(chunk);
                    fileChannel.truncate(0); // Truncate the file before writing
                    fileChannel.write(ByteBuffer.wrap(processedBytes)); // Write processed data to the file
                } catch (Exception e) {
                    e.printStackTrace();
                    log("Error encrypting/decrypting file: " + e.getMessage());
                    return;
                }
                buffer.clear(); // Clear the buffer for reading
            }
        } catch (IOException e) {
            e.printStackTrace();
            log("Error encrypting/decrypting file: " + e.getMessage());
        }
    }

    public static String generateRandomKey(int keyLength) {
        byte[] keyBytes = new byte[keyLength];
        new SecureRandom().nextBytes(keyBytes);
        return Base64.getEncoder().encodeToString(keyBytes);
    }

    public static void main(String[] args) {

        String randomKey = generateRandomKey(16);
        System.out.println("Random Key: " + randomKey);

        SwingUtilities.invokeLater(new Runnable() {
            public void run() {
                new FileEncryptor();
            }
        });
    }
}
