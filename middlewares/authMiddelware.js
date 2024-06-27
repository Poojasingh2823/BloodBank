const jwt = require("jsonwebtoken");

module.exports = (req, res, next) => {
  try {
    // Check if Authorization header exists and is in the correct format
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({
        success: false,
        message: "Authorization header missing or invalid format",
      });
    }

    // Extract token from header
    const token = authHeader.split(" ")[1];

    // Verify JWT token
    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
      if (err) {
        return res.status(401).json({
          success: false,
          message: "Invalid token",
        });
      } else {
        // Attach user ID to request object for further use
        req.userId = decoded.userId;
        next();
      }
    });
  } catch (error) {
    console.error("Authorization middleware error:", error);
    return res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
};
