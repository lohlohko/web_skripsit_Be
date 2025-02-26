const {
  validateUser,
  verifyPassword,
  hashPassword,
  getAESKey,
} = require("../utils/auth");
const pool = require("../config/database");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");

exports.login = async (req, res) => {
  // Validasi method
  if (req.method !== "POST") {
    return res.status(405).json({
      success: false,
      error: "Method not allowed",
    });
  }

  try {
    // Validasi content type
    const contentType = req.headers["content-type"];
    if (!contentType || !contentType.includes("application/json")) {
      return res.status(400).json({
        success: false,
        error: "Content-Type must be application/json",
      });
    }

    const { email, password } = req.body;
    console.log("Login attempt for:", email);

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        error: "Email and password are required",
      });
    }

    let connection;
    try {
      connection = await pool.getConnection();
      // Get user by email
      const [users] = await connection.execute(
        "SELECT id, name,email, role, hashed_password FROM users WHERE email = ?",
        [email]
      );

      if (users.length === 0) {
        return res.status(401).json({ message: "Invalid email or password" });
      }

      const user = users[0];

      // Verify password dengan Argon2
      const isValid = await verifyPassword(password, user.hashed_password);

      if (!isValid) {
        return res.status(401).json({ message: "Invalid email or password" });
      }

      console.log("Login successful for user:", {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
      });

      // Buat JWT token
      const token = jwt.sign(
        {
          id: user.id,
          role: user.role,
        },
        process.env.JWT_SECRET,
        { expiresIn: "24h" }
      );

      // Set JWT dalam httpOnly cookie
      res.cookie("jwt", token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "strict",
        maxAge: 24 * 60 * 60 * 1000, // 24 jam
      });

      // Kirim response tanpa menyertakan sensitive data
      return res.json({
        success: true,
        message: "Login successful",
        user: {
          name: user.name,
          role: user.role,
        },
      });
    } finally {
      if (connection) connection.release();
    }
  } catch (error) {
    console.error("Login error:", error);
    return res.status(400).json({
      success: false,
      message: "Login failed",
      error: error.message || "Invalid credentials",
    });
  }
};

// Tambahkan fungsi register
exports.register = async (req, res) => {
  let connection;
  try {
    const { name, email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: "Email dan password harus diisi",
      });
    }

    connection = await pool.getConnection();

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

    // Ganti ke hashPassword
    const hashedPassword = await hashPassword(password);

    const [result] = await pool.query(
      "INSERT INTO users (name, email, hashed_password, role) VALUES (?, ?, ?, ?)",
      [name, email, hashedPassword, "user"]
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
