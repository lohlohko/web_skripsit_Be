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

    connection = await pool.getConnection();

    // 1. Simpan data terenkripsi ke tabel user_details
    await connection.query(
      `INSERT INTO user_details 
        (user_id, encrypted_fullname, encrypted_phone, encrypted_address, encrypted_nik, is_verified) 
       VALUES (?, ?, ?, ?, ?, 1)
       ON DUPLICATE KEY UPDATE 
        encrypted_fullname = VALUES(encrypted_fullname),
        encrypted_phone = VALUES(encrypted_phone),
        encrypted_address = VALUES(encrypted_address),
        encrypted_nik = VALUES(encrypted_nik),
        is_verified = 1`,
      [userId, fullName, phone, address, nik]
    );

    // 2. Update status di tabel users
    await connection.query(
      `UPDATE users SET 
        status = 'verified'
       WHERE id = ?`,
      [userId]
    );

    return res.json({
      success: true,
      message: "Profile updated successfully",
    });
  } catch (error) {
    console.error("Error updating profile:", error);
    return res.status(500).json({
      success: false,
      message: "Failed to update profile",
    });
  } finally {
    if (connection) connection.release();
  }
};

exports.getProfile = async (req, res) => {
  let connection;
  try {
    const userId = req.user.id;

    // Ambil data user termasuk encrypted_aes_key
    const [user] = await pool.query(
      `SELECT u.email, u.encrypted_aes_key, ud.* 
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

    // Kirim data terenkripsi ke client
    res.json({
      success: true,
      user: {
        email: user[0].email,
        encrypted_fullname: user[0].encrypted_fullname || null,
        encrypted_nik: user[0].encrypted_nik || null,
        encrypted_phone: user[0].encrypted_phone || null,
        encrypted_address: user[0].encrypted_address || null,
        isVerified: user[0].is_verified === 1,
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
  let connection;
  try {
    connection = await pool.getConnection();

    // Check both users and user_details tables
    const [result] = await connection.query(
      `SELECT u.status, ud.is_verified 
       FROM users u 
       LEFT JOIN user_details ud ON u.id = ud.user_id 
       WHERE u.id = ?`,
      [req.user.id]
    );

    // User dianggap terverifikasi jika status di users = 'verified'
    // DAN is_verified di user_details = 1
    const isVerified =
      result[0]?.status === "verified" && result[0]?.is_verified === 1;

    res.json({
      success: true,
      status: isVerified ? "verified" : "pending",
    });
  } catch (error) {
    console.error("Error checking verification status:", error);
    res.status(500).json({
      success: false,
      error: "Failed to check verification status",
    });
  } finally {
    if (connection) connection.release();
  }
};
