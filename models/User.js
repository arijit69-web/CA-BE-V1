const mongoose = require("mongoose");

const userSchema = new mongoose.Schema(
    {
        name: {
            type: String,
            required: true,
            trim: true,
        },       
        email: {
            type: String,
            required: true,
            trim: true,
        },
        password: {
            type: String,
        },
        accountType: {
            type: String,
            enum: ["Admin", "Student"],
            required: true,
        },           
        additionalDetails: {
            type: mongoose.Schema.Types.ObjectId,
            required: true,
            ref: "Profile",
        },       
        image: {
            type: String,
            required: true,
        }      

    },
    { timestamps: true }
);

module.exports = mongoose.model("User", userSchema);