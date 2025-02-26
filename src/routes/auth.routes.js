const express = require("express");
const router = express.Router();
const authController = require("../controllers/authController");
const { verifyAuth} = require("../middleware/auth");

// Public routes
router.post("/register", authController.register);
router.post("/login", authController.login);
router.post("/logout", authController.logout);
router.post("/reset-password-request", authController.resetPasswordRequest);
router.get("/verify", verifyAuth, authController.verifyToken);

// Protected routes
router.get("/role", verifyAuth, (req, res) => {
  res.json({ role: req.user.role });
});

module.exports = router;
