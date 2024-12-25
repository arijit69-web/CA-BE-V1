const express = require("express");
const {
    postJob,
    getAllJobs,
    getJobById,
    getJobsByEmail,
    deleteJob,
    updateJob,
} = require("../controllers/jobController");
const asyncWrapper = require("../middleware/asyncWrapper");

const router = express.Router();

router.post("/post-job", asyncWrapper(postJob));
router.get("/all-jobs", asyncWrapper(getAllJobs));
router.get("/all-jobs/:id", asyncWrapper(getJobById));
router.get("/my-jobs/:email", asyncWrapper(getJobsByEmail));
router.delete("/job/:id", asyncWrapper(deleteJob));
router.patch("/update-job/:id", asyncWrapper(updateJob));

module.exports = router;
