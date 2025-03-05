const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const pool = require("../config/database");

// Fungsi register menerima password yang sudah di-hash dari client
exports.register = async (req, res) => {
  let connection;
  try {
    // 1. Terima data yang sudah di-hash dari client
    const { name, email, hashed_password } = req.body;

    // 2. Validasi input
    if (!email || !hashed_password || !name) {
      return res.status(400).json({
        success: false,
        message: "Email, password, and name are required",
      });
    }

    connection = await pool.getConnection();

    // 3. Cek email duplikat
    const [existingUser] = await connection.execute(
      "SELECT * FROM users WHERE email = ?",
      [email]
    );

    if (existingUser.length > 0) {
      return res.status(400).json({
        success: false,
        message: "Email sudah terdaftar",
      });
    }

    // 4. Simpan ke database (password sudah dalam bentuk hash)
    const [result] = await connection.query(
      "INSERT INTO users (name, email, hashed_password, role, status) VALUES (?, ?, ?, ?, ?)",
      [name, email, hashed_password, "user", "pending"]
    );

    return res.status(201).json({
      success: true,
      message: "Registrasi berhasil",
      userId: result.insertId,
    });
  } catch (error) {
    console.error("Registration error:", error);
    return res.status(500).json({
      success: false,
      message: "Terjadi kesalahan saat registrasi",
      error: error.message,
    });
  } finally {
    if (connection) connection.release();
  }
};

exports.login = async (req, res) => {
  let connection;
  try {
    const { email, hashed_password } = req.body;

    if (!email || !hashed_password) {
      return res.status(400).json({
        success: false,
        error: "Email and password are required",
      });
    }

    connection = await pool.getConnection();

    // Get user by email
    const [users] = await connection.execute(
      "SELECT id, name, email, role, hashed_password FROM users WHERE email = ?",
      [email]
    );

    if (users.length === 0) {
      return res.status(401).json({
        success: false,
        message: "Invalid email or password",
      });
    }

    const user = users[0];

    // Verify hashed password
    if (user.hashed_password !== hashed_password) {
      return res.status(401).json({
        success: false,
        message: "Invalid email or password",
      });
    }

    // Generate new public key
    const publicKey = crypto.randomBytes(32).toString("hex");

    // Update public key di database
    await connection.query(
      `UPDATE users 
       SET public_key = ?, 
           key_expires_at = DATE_ADD(NOW(), INTERVAL 24 HOUR) 
       WHERE id = ?`,
      [publicKey, user.id]
    );

    // Create JWT token
    const token = jwt.sign(
      { id: user.id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "24h" }
    );

    // Set JWT in httpOnly cookie
    res.cookie("jwt", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 24 * 60 * 60 * 1000, // 24 hours
    });

    // Send response dengan public key
    return res.json({
      success: true,
      message: "Login successful",
      user: {
        name: user.name,
        role: user.role,
      },
      publicKey: publicKey, // Kirim public key untuk enkripsi data
    });
  } catch (error) {
    console.error("Login error:", error);
    return res.status(500).json({
      success: false,
      message: "Login failed",
      error: error.message,
    });
  } finally {
    if (connection) connection.release();
  }
};

// Tambahkan fungsi logout
exports.logout = async (req, res) => {
  try {
    // Hapus JWT cookie
    res.cookie("jwt", "", {
      httpOnly: true,
      expires: new Date(0),
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
    });

    return res.json({
      success: true,
      message: "Logged out successfully",
    });
  } catch (error) {
    console.error("Logout error:", error);
    return res.status(500).json({
      success: false,
      error: "Logout failed",
    });
  }
};

exports.resetPasswordRequest = async (req, res) => {
  let connection;
  try {
    connection = await pool.getConnection();
    const { email } = req.body;

    const resetToken = crypto.randomBytes(32).toString("hex");
    const tokenExpiry = new Date();
    tokenExpiry.setHours(tokenExpiry.getHours() + 1);

    await connection.execute(
      "UPDATE users SET reset_token = ?, token_expiry = ? WHERE email = ?",
      [resetToken, tokenExpiry, email]
    );

    // Here you would typically send an email with the reset token
    res.json({ message: "Password reset instructions sent to email" });
  } catch (error) {
    console.error("Reset request error:", error);
    res.status(500).json({ message: "Server error during reset request" });
  } finally {
    if (connection) connection.release();
  }
};

exports.verifyToken = async (req, res) => {
  try {
    return res.json({
      success: true,
      role: req.user.role,
      name: req.user.name,
      email: req.user.email,
    });
  } catch (error) {
    console.error("Token verification error:", error);
    return res.status(401).json({
      success: false,
      error: "Invalid token",
    });
  }
};
