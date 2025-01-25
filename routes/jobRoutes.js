const express = require("express");
const {
    getAllJobs,
  
} = require("../controllers/jobController");
const asyncWrapper = require("../middleware/asyncWrapper");
const { auth } = require("../middleware/auth")

const router = express.Router();

router.get("/all-jobs",auth, asyncWrapper(getAllJobs));


module.exports = router;
