import java.sql.*;

public class DBInsertTest {
    public static void main(String[] args) {
        String url = "jdbc:mysql://localhost:3306/digital_forensics?useSSL=false&serverTimezone=UTC";
        String user = "root";
        String pass = "root";

        try {
            Class.forName("com.mysql.cj.jdbc.Driver");
            Connection conn = DriverManager.getConnection(url, user, pass);
            System.out.println("Database connected successfully!");

            // Insert test row
            String insertSQL = "INSERT INTO file_hashes (file_name, file_path, hash_value, timestamp) VALUES (?, ?, ?, ?)";
            PreparedStatement ps = conn.prepareStatement(insertSQL);
            ps.setString(1, "test_file.java");
            ps.setString(2, "C:/temp/test_file.java");
            ps.setString(3, "dummyhash123");
            ps.setLong(4, System.currentTimeMillis());

            int rows = ps.executeUpdate();
            if (rows > 0) {
                System.out.println("Insert successful!");
            }

            // Read back the row
            String selectSQL = "SELECT * FROM file_hashes WHERE file_name = ?";
            PreparedStatement ps2 = conn.prepareStatement(selectSQL);
            ps2.setString(1, "test_file.java");
            ResultSet rs = ps2.executeQuery();

            while (rs.next()) {
                System.out.println("Row found:");
                System.out.println("ID: " + rs.getInt("id"));
                System.out.println("File Name: " + rs.getString("file_name"));
                System.out.println("File Path: " + rs.getString("file_path"));
                System.out.println("Hash: " + rs.getString("hash_value"));
                System.out.println("Timestamp: " + rs.getLong("timestamp"));
            }

            conn.close();
        } catch (ClassNotFoundException e) {
            System.out.println("MySQL Driver not found!");
            e.printStackTrace();
        } catch (SQLException e) {
            System.out.println("Database error!");
            e.printStackTrace();
        }
    }
}
