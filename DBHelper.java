/*import java.sql.*;

public class DBHelper {
    private static final String URL = "jdbc:mysql://localhost:3306/digital_forensics";
    private static final String USER = "root"; // replace with your MySQL username
    private static final String PASS = "root"; // replace with your MySQL password

    static {
        try {
            Class.forName("com.mysql.cj.jdbc.Driver");
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
    }

    // ============ Insert file hash ============
    public static void insertFileHash(String fileName, String filePath, String hashValue, long timestamp) {
        String sql = "INSERT INTO file_hashes (file_name, file_path, hash_value, timestamp) VALUES (?, ?, ?, ?)";
        try (Connection conn = DriverManager.getConnection(URL, USER, PASS);
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, fileName);
            ps.setString(2, filePath);
            ps.setString(3, hashValue);
            ps.setLong(4, timestamp);
            ps.executeUpdate();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    // ============ Insert recovered file ============
    public static void insertRecoveredFile(String fileName, String sourcePath, String destPath, long timestamp) {
        String sql = "INSERT INTO recovered_files (file_name, source_path, dest_path, timestamp) VALUES (?, ?, ?, ?)";
        try (Connection conn = DriverManager.getConnection(URL, USER, PASS);
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, fileName);
            ps.setString(2, sourcePath);
            ps.setString(3, destPath);
            ps.setLong(4, timestamp);
            ps.executeUpdate();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    // ============ Insert encrypted report ============
    public static void insertEncryptedReport(String fileName, String filePath, long timestamp) {
        String sql = "INSERT INTO encrypted_reports (file_name, file_path, timestamp) VALUES (?, ?, ?)";
        try (Connection conn = DriverManager.getConnection(URL, USER, PASS);
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, fileName);
            ps.setString(2, filePath);
            ps.setLong(3, timestamp);
            ps.executeUpdate();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
}
*/
import java.sql.*;

public class DBHelper {
    private static final String URL = "jdbc:mysql://localhost:3306/digital_forensics";
    private static final String USER = "root"; // your MySQL username
    private static final String PASS = "root"; // your MySQL password

    static {
        try {
            Class.forName("com.mysql.cj.jdbc.Driver");
            System.out.println("MySQL JDBC Driver Registered!");
        } catch (ClassNotFoundException e) {
            System.out.println("MySQL JDBC Driver not found!");
            e.printStackTrace();
        }
    }

    // ============ Insert file hash ============
    public static void insertFileHash(String fileName, String filePath, String hashValue, long timestamp) {
        String sql = "INSERT INTO file_hashes (file_name, file_path, hash_value, timestamp) VALUES (?, ?, ?, ?)";
        try (Connection conn = DriverManager.getConnection(URL, USER, PASS);
             PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setString(1, fileName);
            ps.setString(2, filePath);
            ps.setString(3, hashValue);
            ps.setLong(4, timestamp);

            int rows = ps.executeUpdate();
            if (rows > 0) {
                System.out.println("File hash inserted successfully: " + fileName);
            } else {
                System.out.println("File hash insert failed: " + fileName);
            }

        } catch (SQLException e) {
            System.out.println("Error inserting file hash for: " + fileName);
            e.printStackTrace();
        }
    }

    // ============ Insert recovered file ============
    public static void insertRecoveredFile(String fileName, String sourcePath, String destPath, long timestamp) {
        String sql = "INSERT INTO recovered_files (file_name, source_path, dest_path, timestamp) VALUES (?, ?, ?, ?)";
        try (Connection conn = DriverManager.getConnection(URL, USER, PASS);
             PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setString(1, fileName);
            ps.setString(2, sourcePath);
            ps.setString(3, destPath);
            ps.setLong(4, timestamp);

            int rows = ps.executeUpdate();
            if (rows > 0) {
                System.out.println("Recovered file inserted successfully: " + fileName);
            } else {
                System.out.println("Recovered file insert failed: " + fileName);
            }

        } catch (SQLException e) {
            System.out.println("Error inserting recovered file for: " + fileName);
            e.printStackTrace();
        }
    }

    // ============ Insert encrypted report ============
    public static void insertEncryptedReport(String fileName, String filePath, long timestamp) {
        String sql = "INSERT INTO encrypted_reports (file_name, file_path, timestamp) VALUES (?, ?, ?)";
        try (Connection conn = DriverManager.getConnection(URL, USER, PASS);
             PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setString(1, fileName);
            ps.setString(2, filePath);
            ps.setLong(3, timestamp);

            int rows = ps.executeUpdate();
            if (rows > 0) {
                System.out.println("Encrypted report inserted successfully: " + fileName);
            } else {
                System.out.println("Encrypted report insert failed: " + fileName);
            }

        } catch (SQLException e) {
            System.out.println("Error inserting encrypted report for: " + fileName);
            e.printStackTrace();
        }
    }
}
