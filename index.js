const express = require("express");
const dotenv = require("dotenv");
const cors = require("cors");
const logger = require("./config/logger");
const database = require("./config/database");
const jobRoutes = require("./routes/jobRoutes");
const errorHandler = require("./middleware/errorHandler");

dotenv.config();
const app = express();
const PORT = process.env.PORT || 3000;

// Connect to database
database.connect();

// Middleware
app.use(express.json());
app.use(cors());

// Routes
app.use("/api/v1/jobs", jobRoutes);

// Health Check
app.get("/", (req, res) => {
    return res.status(200).json({ success: true, message: "API is running" });
});

// Global Error Handler
app.use(errorHandler);

// Start Server
app.listen(PORT, () => {
    logger.info(`Server running on port ${PORT}`);
});
