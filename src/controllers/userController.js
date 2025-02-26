const pool = require("../config/database");
const { getAESKey, encrypt, decrypt } = require("../utils/encryption");

exports.getRole = async (req, res) => {
  try {
    const token = req.cookies.token;

    if (!token) {
      return res
        .status(401)
        .json({ success: false, error: "Not authenticated" });
    }

    // Query database dengan prepared statement
    const [rows] = await pool.query("SELECT role FROM users WHERE id = ?", [
      token,
    ]);

    if (!rows || rows.length === 0) {
      return res.status(404).json({ success: false, error: "User not found" });
    }

    return res.json({
      success: true,
      role: rows[0].role,
    });
  } catch (error) {
    console.error("Error fetching user role:", error);
    return res.status(500).json({
      success: false,
      error: "Internal server error",
    });
  }
};

exports.completeProfile = async (req, res) => {
  let connection;
  try {
    const { fullName, nik, phone, address } = req.body;
    const userId = req.user.id;

    // Ambil hash password user dari database untuk enkripsi
    const [user] = await pool.query(
      "SELECT hashed_password FROM users WHERE id = ?",
      [userId]
    );

    if (!user || !user[0]) {
      throw new Error("User not found");
    }

    // Gunakan hash password sebagai key AES
    const encryptionKey = Buffer.from(user[0].hashed_password, "hex");

    connection = await pool.getConnection();

    // Enkripsi data sensitif
    const encryptedNik = encrypt(nik, encryptionKey);
    const encryptedPhone = encrypt(phone, encryptionKey);
    const encryptedAddress = encrypt(address, encryptionKey);
    const encryptedFullName = encrypt(fullName, encryptionKey);

    // Update user_details
    await connection.execute(
      `INSERT INTO user_details 
        (user_id, encrypted_fullname, encrypted_nik, encrypted_phone, encrypted_address, is_verified) 
      VALUES (?, ?, ?, ?, ?, true)
      ON DUPLICATE KEY UPDATE 
        encrypted_fullname = VALUES(encrypted_fullname),
        encrypted_nik = VALUES(encrypted_nik),
        encrypted_phone = VALUES(encrypted_phone),
        encrypted_address = VALUES(encrypted_address),
        is_verified = true`,
      [
        userId,
        encryptedFullName,
        encryptedNik,
        encryptedPhone,
        encryptedAddress,
      ]
    );

    // Update status user
    await connection.execute(
      "UPDATE users SET status = 'verified' WHERE id = ?",
      [userId]
    );

    res.json({
      success: true,
      message: "Profile updated successfully",
    });
  } catch (error) {
    console.error("Error completing profile:", error);
    res.status(500).json({
      success: false,
      error: "Failed to update profile",
    });
  } finally {
    if (connection) connection.release();
  }
};

exports.getProfile = async (req, res) => {
  let connection;
  try {
    const userId = req.user.id;

    // Ambil data user dan hash password
    const [user] = await pool.query(
      `SELECT u.hashed_password, u.email, ud.* 
       FROM users u 
       LEFT JOIN user_details ud ON u.id = ud.user_id 
       WHERE u.id = ?`,
      [userId]
    );

    if (!user[0]) {
      return res.status(404).json({
        success: false,
        error: "User not found",
      });
    }

    // Gunakan hash password sebagai key untuk dekripsi
    const encryptionKey = Buffer.from(user[0].hashed_password, "hex");

    // Dekripsi data sensitif
    const decryptedData = {
      fullName: user[0].encrypted_fullname
        ? decrypt(user[0].encrypted_fullname, encryptionKey)
        : null,
      nik: user[0].encrypted_nik
        ? decrypt(user[0].encrypted_nik, encryptionKey)
        : null,
      phone: user[0].encrypted_phone
        ? decrypt(user[0].encrypted_phone, encryptionKey)
        : null,
      address: user[0].encrypted_address
        ? decrypt(user[0].encrypted_address, encryptionKey)
        : null,
    };

    res.json({
      success: true,
      user: {
        email: user[0].email,
        ...decryptedData,
        isVerified: user[0].is_verified,
      },
    });
  } catch (error) {
    console.error("Error getting profile:", error);
    res.status(500).json({
      success: false,
      error: "Failed to get profile",
    });
  } finally {
    if (connection) connection.release();
  }
};

exports.checkVerificationStatus = async (req, res) => {
  try {
    const [user] = await pool.query("SELECT status FROM users WHERE id = ?", [
      req.user.id,
    ]);

    res.json({
      success: true,
      status: user[0]?.status || "unverified",
    });
  } catch (error) {
    console.error("Error checking verification status:", error);
    res.status(500).json({
      success: false,
      error: "Failed to check verification status",
    });
  }
};
