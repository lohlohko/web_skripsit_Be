const pool = require("../config/database");
const argon2 = require("argon2");

// Salt tetap untuk konsistensi hash
const FIXED_SALT = Buffer.from("LibraryAppSalt2024", "utf-8");

// Fungsi untuk validasi user
async function validateUser({ email, password }) {
  const [users] = await pool.query("SELECT * FROM users WHERE email = ?", [
    email,
  ]);

  if (users.length === 0) {
    throw new Error("Invalid credentials");
  }

  const user = users[0];

  // Verifikasi password
  const isValid = await verifyPassword(password, user.hashed_password);
  if (!isValid) {
    throw new Error("Invalid credentials");
  }

  return user;
}

// Fungsi untuk hash password
async function hashPassword(password) {
  try {
    // Generate hash 16 bytes dengan salt tetap
    const hash = await argon2.hash(password, {
      type: argon2.argon2id,
      memoryCost: 2 ** 16,
      timeCost: 3,
      parallelism: 1,
      hashLength: 16, // 16 bytes untuk AES-128
      salt: FIXED_SALT,
      raw: true,
    });

    // Return dalam format hex
    return hash.toString("hex");
  } catch (err) {
    throw new Error("Error hashing password");
  }
}

// Fungsi untuk verifikasi password
async function verifyPassword(password, storedHash) {
  try {
    // Hash password input dan bandingkan
    const inputHash = await hashPassword(password);
    return inputHash === storedHash;
  } catch (err) {
    throw new Error("Error verifying password");
  }
}

// Fungsi untuk mendapatkan kunci AES dari hash yang tersimpan
function getAESKey(storedHash) {
  // Convert hex string ke buffer 16 bytes untuk AES
  return Buffer.from(storedHash, "hex");
}

async function createUser({ email, password }) {
  const [existingUsers] = await pool.query(
    "SELECT * FROM users WHERE email = ?",
    [email]
  );

  if (existingUsers.length > 0) {
    throw new Error("Email already registered");
  }

  const hashedPassword = await hashPassword(password);

  const [result] = await pool.query(
    "INSERT INTO users (email, hashed_password, role) VALUES (?, ?, ?)",
    [email, hashedPassword, "user"]
  );

  const [newUser] = await pool.query(
    "SELECT id, email, role FROM users WHERE id = ?",
    [result.insertId]
  );

  return newUser[0];
}

module.exports = {
  validateUser,
  createUser,
  hashPassword,
  verifyPassword,
  getAESKey,
};
