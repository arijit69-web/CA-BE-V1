const { ObjectId } = require("mongodb");
const { getJobCollection } = require("../models/jobModel");
const logger = require("../config/logger");

// Post a job
const postJob = async (req, res) => {
    const jobData = { ...req.body, createdAt: new Date() };

    try {
        const result = await getJobCollection().insertOne(jobData);
        logger.info("Job successfully posted", { jobId: result.insertedId });
        return res.status(201).json({ success: true, data: result });
    } catch (error) {
        logger.error("Error posting job", { error });
        throw new Error("Failed to post job");
    }
};

// Get all jobs
const getAllJobs = async (req, res) => {
    try {
        const jobs = await getJobCollection().find({}).sort({ createdAt: -1 }).toArray();
        return res.status(200).json({ success: true, data: jobs });
    } catch (error) {
        logger.error("Error fetching jobs", { error });
        throw new Error("Failed to fetch jobs");
    }
};

// Get a job by ID
const getJobById = async (req, res) => {
    try {
        const job = await getJobCollection().findOne({ _id: new ObjectId(req.params.id) });
        if (!job) {
            throw new Error("Job not found");
        }
        return res.status(200).json({ success: true, data: job });
    } catch (error) {
        logger.error("Error fetching job by ID", { id: req.params.id, error });
        throw new Error("Failed to fetch job");
    }
};

// Get jobs by email
const getJobsByEmail = async (req, res) => {
    try {
        const jobs = await getJobCollection().find({ postedBy: req.params.email }).toArray();
        return res.status(200).json({ success: true, data: jobs });
    } catch (error) {
        logger.error("Error fetching jobs by email", { email: req.params.email, error });
        throw new Error("Failed to fetch jobs");
    }
};

// Delete a job
const deleteJob = async (req, res) => {
    try {
        const result = await getJobCollection().deleteOne({ _id: new ObjectId(req.params.id) });
        if (result.deletedCount === 0) {
            throw new Error("Job not found");
        }
        logger.info("Job successfully deleted", { jobId: req.params.id });
        return res.status(200).json({ success: true, data: result });
    } catch (error) {
        logger.error("Error deleting job", { id: req.params.id, error });
        throw new Error("Failed to delete job");
    }
};

// Update a job
const updateJob = async (req, res) => {
    try {
        const updateDoc = { $set: { ...req.body } };
        const result = await getJobCollection().updateOne(
            { _id: new ObjectId(req.params.id) },
            updateDoc,
            { upsert: true }
        );

        if (result.matchedCount === 0) {
            throw new Error("Job not found");
        }
        logger.info("Job successfully updated", { jobId: req.params.id });
        return res.status(200).json({ success: true, data: result });
    } catch (error) {
        logger.error("Error updating job", { id: req.params.id, error });
        throw new Error("Failed to update job");
    }
};

module.exports = { postJob, getAllJobs, getJobById, getJobsByEmail, deleteJob, updateJob };
