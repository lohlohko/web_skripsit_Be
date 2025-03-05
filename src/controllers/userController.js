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
    const userId = req.user.id;
    const { encrypted_profile, encrypted_AES_key } = req.body;

    if (!encrypted_profile || !encrypted_AES_key) {
      return res.status(400).json({
        success: false,
        error: "Missing required encrypted data",
      });
    }

    connection = await pool.getConnection();

    // 1. Cek apakah user sudah pernah mengisi profil
    const [existingProfile] = await connection.query(
      "SELECT id FROM user_details WHERE user_id = ?",
      [userId]
    );

    let query;
    let params;

    if (existingProfile.length > 0) {
      // Update jika profil sudah ada
      query = `
        UPDATE user_details 
        SET encrypted_fullname = ?,
            encrypted_nik = ?,
            encrypted_phone = ?,
            encrypted_address = ?,
            encrypted_aes_key = ?,
            is_verified = 1,
            updated_at = NOW()
        WHERE user_id = ?
      `;
      params = [
        encrypted_profile.fullName,
        encrypted_profile.nik,
        encrypted_profile.phone,
        encrypted_profile.address,
        encrypted_AES_key,
        userId,
      ];
    } else {
      // Insert jika profil belum ada
      query = `
        INSERT INTO user_details (
          user_id,
          encrypted_fullname,
          encrypted_nik,
          encrypted_phone,
          encrypted_address,
          encrypted_aes_key,
          is_verified,
          created_at,
          updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, 1, NOW(), NOW())
      `;
      params = [
        userId,
        encrypted_profile.fullName,
        encrypted_profile.nik,
        encrypted_profile.phone,
        encrypted_profile.address,
        encrypted_AES_key,
      ];
    }

    // Eksekusi query untuk user_details
    await connection.query(query, params);

    // Update status di tabel users menjadi 'verified'
    await connection.query(
      `UPDATE users SET status = 'verified' WHERE id = ?`,
      [userId]
    );

    res.json({
      success: true,
      message: "Profile updated successfully",
      isVerified: true,
      status: "verified",
    });
  } catch (error) {
    console.error("Error in complete profile:", error);
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

    // Ambil data terenkripsi dari database
    const [user] = await pool.query(
      `SELECT u.email, ud.encrypted_fullname, ud.encrypted_nik, 
              ud.encrypted_phone, ud.encrypted_address, ud.encrypted_aes_key,
              ud.is_verified, u.status
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
        encrypted_fullname: user[0].encrypted_fullname,
        encrypted_nik: user[0].encrypted_nik,
        encrypted_phone: user[0].encrypted_phone,
        encrypted_address: user[0].encrypted_address,
        encrypted_aes_key: user[0].encrypted_aes_key,
        isVerified: user[0].is_verified === 1,
        status: user[0].status
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

// Fungsi untuk mendapatkan status verifikasi
exports.getVerificationStatus = async (req, res) => {
  let connection;
  try {
    const userId = req.user.id;

    connection = await pool.getConnection();
    const [user] = await connection.query(
      "SELECT status FROM users WHERE id = ?",
      [userId]
    );

    res.json({
      success: true,
      status: user[0].status,
    });
  } catch (error) {
    console.error("Error getting verification status:", error);
    res.status(500).json({
      success: false,
      error: "Failed to get verification status",
    });
  } finally {
    if (connection) connection.release();
  }
};
