const express = require("express");
const router = express.Router();
const userController = require("../controllers/userController");
const { verifyAuth } = require("../middleware/auth");

router.post("/complete-profile", verifyAuth, userController.completeProfile);
router.get(
  "/verification-status",
  verifyAuth,
  userController.checkVerificationStatus
);
router.get("/profile", verifyAuth, userController.getProfile);

module.exports = router;
