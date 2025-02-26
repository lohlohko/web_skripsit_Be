const pool = require("../config/database");
const { getAESKey } = require("../utils/auth");

const adminController = {
  getUsers: async (req, res) => {
    try {
      // Tambahkan DISTINCT untuk menghindari duplikasi
      const [users] = await pool.query(`
        SELECT DISTINCT
          u.id,
          u.email,
          u.role,
          u.status,
          u.created_at,
          CASE 
            WHEN ud.encrypted_fullname IS NOT NULL THEN true 
            ELSE false 
          END as has_profile
        FROM users u
        LEFT JOIN user_details ud ON u.id = ud.user_id
        ORDER BY u.created_at DESC
      `);

      res.json({
        success: true,
        users: users.map((user) => ({
          ...user,
          has_profile: !!user.has_profile,
        })),
      });
    } catch (error) {
      console.error("Error getting users:", error);
      res.status(500).json({
        success: false,
        error: "Failed to get users",
      });
    }
  },

  getUserDetails: async (req, res) => {
    try {
      const userId = req.params.userId;

      const [user] = await pool.query(
        `
        SELECT 
          u.id,
          u.email,
          u.role,
          u.status,
          u.created_at,
          CASE 
            WHEN ud.encrypted_fullname IS NOT NULL THEN true 
            ELSE false 
          END as has_profile
        FROM users u
        LEFT JOIN user_details ud ON u.id = ud.user_id
        WHERE u.id = ?
      `,
        [userId]
      );

      if (!user[0]) {
        return res.status(404).json({
          success: false,
          error: "User not found",
        });
      }

      res.json({
        success: true,
        user: {
          ...user[0],
          has_profile: !!user[0].has_profile,
        },
      });
    } catch (error) {
      console.error("Error getting user details:", error);
      res.status(500).json({
        success: false,
        error: "Failed to get user details",
      });
    }
  },
};

module.exports = adminController;
