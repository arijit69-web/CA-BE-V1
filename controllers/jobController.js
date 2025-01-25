const { ObjectId } = require("mongodb");
const  Job  = require("../models/jobModel");
const logger = require("../config/logger");

// Get all jobs
const getAllJobs = async (req, res) => {
    try {        
        const jobs = await Job.find({}).sort({ createdAt: -1 }).exec();
        return res.status(200).json({ success: true, data: jobs });
    } catch (error) {
        logger.error("Error fetching jobs", { error });
        throw new Error(`Failed to fetch jobs: ${error}`);
    }
};

module.exports = {  getAllJobs };
