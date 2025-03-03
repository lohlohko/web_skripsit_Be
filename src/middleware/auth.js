const pool = require("../config/database");
const jwt = require("jsonwebtoken");

exports.verifyAuth = async (req, res, next) => {
  try {
    // Ambil token dari cookie
    const token = req.cookies.jwt;

    if (!token) {
      return res.status(401).json({
        success: false,
        error: "Not authenticated",
      });
    }

    // Verifikasi token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // Tambahkan error handling untuk koneksi database
    let connection;
    try {
      connection = await pool.getConnection();

      // Dapatkan user dari database
      const [users] = await connection.query(
        "SELECT id, name, email, role FROM users WHERE id = ?",
        [decoded.id]
      );

      if (!users || users.length === 0) {
        return res.status(401).json({
          success: false,
          error: "Invalid token",
        });
      }

      // Tambahkan data user ke request
      req.user = users[0];

      next();
    } catch (dbError) {
      console.error("Database connection error:", dbError);
      return res.status(500).json({
        success: false,
        error: "Database connection failed",
      });
    } finally {
      if (connection) connection.release();
    }
  } catch (error) {
    console.error("Auth middleware error:", error);
    return res.status(401).json({
      success: false,
      error: "Authentication failed",
    });
  }
};

// Middleware untuk cek role admin
exports.requireAdmin = async (req, res, next) => {
  if (!req.user || req.user.role !== "admin") {
    return res.status(403).json({
      success: false,
      error: "Access denied",
    });
  }
  next();
};
