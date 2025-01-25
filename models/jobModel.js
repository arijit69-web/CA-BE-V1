const mongoose = require('mongoose');

const jobPostingSchema = new mongoose.Schema({
  
  jobTitle: {
    type: String,
  },
  companyName: {
    type: String,
  },
  minPrice: {
    type: Number,
  },
  maxPrice: {
    type: Number,
  },
  salaryType: {
    type: String,
    enum: ['hourly', 'weekly', 'monthly', 'yearly'],
  },
  jobLocation: {
    type: String,
  },
  postingDate: {
    type: Date,
  },
  experienceLevel: {
    type: String,
    enum: ['NoExperience', 'EntryLevel', 'MidLevel', 'SeniorLevel'],
  },
  companyLogo: {
    type: String,
  },
  employmentType: {
    type: String,
    enum: ['Remote', 'Hybrid', 'In-Office'],
  },
  jobUrl: {
    type: String,
  },
  postedBy: {
    type: String,
  },
  skills: {
    type: [String],
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
});

module.exports = mongoose.model('Job', jobPostingSchema);
