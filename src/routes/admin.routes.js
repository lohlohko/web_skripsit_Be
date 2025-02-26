const express = require("express");
const router = express.Router();
const adminController = require("../controllers/adminController");
const { verifyAuth, requireAdmin } = require("../middleware/auth");

router.get("/users", verifyAuth, requireAdmin, adminController.getUsers);
router.get(
  "/users/:userId",
  verifyAuth,
  requireAdmin,
  adminController.getUserDetails
);

module.exports = router;
