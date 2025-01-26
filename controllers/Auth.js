const bcrypt = require("bcrypt");
const User = require("../models/User");
const jwt = require("jsonwebtoken");
const Profile = require("../models/Profile");
require("dotenv").config();
const { oauth2Client } = require('../utils/googleClient');
const axios = require('axios');


exports.signup = async (req, res) => {
    try {
        const {
            name,
            email,
            password,
            confirmPassword,
            accountType,
        } = req.body;
        if (
            !name ||
            !email ||
            !password ||
            !confirmPassword
        ) {
            return res.status(403).send({
                success: false,
                message: "Please Fill up All the Required Fields",
            });
        }
        if (password !== confirmPassword) {
            return res.status(400).json({
                success: false,
                message:
                    "Password and Confirm Password do not match. Please try again.",
            });
        }

        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({
                success: false,
                message: "User already exists. Please sign in to continue.",
            });
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create the Additional Profile For User
        const profileDetails = await Profile.create({
            gender: null,
            dateOfBirth: null,
            about: null,
            contactNumber: null,
        });
        const user = await User.create({
            name,
            email,
            password: hashedPassword,
            accountType: accountType,
            additionalDetails: profileDetails._id,
            image: `https://api.dicebear.com/5.x/initials/svg?seed=${firstName} ${lastName}`,
        });
        user.password = undefined;

        return res.status(200).json({
            success: true,
            user,
            message: "User Registered Successfully",
        });
    } catch (error) {
        return res.status(500).json({
            success: false,
            message: "User Cannot be Registered. Please Try Again.",
        });
    }
};


exports.login = async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({
                success: false,
                message: `Please Fill up All the Required Fields`,
            });
        }

        const user = await User.findOne({ email }).populate("additionalDetails");

        if (!user) {
            // Return 401 Unauthorized status code with error message
            return res.status(401).json({
                success: false,
                message: `User is Not Registered`,
            });
        }

        // Generate JWT token and Compare Password
        if (await bcrypt.compare(password, user.password)) {
            const token = jwt.sign(
                { email: user.email, id: user._id, accountType: user.accountType },
                process.env.JWT_SECRET,
                {
                    expiresIn: "24h",
                }
            );

            user.token = token;
            user.password = undefined;
            // Set cookie for token and return success response
            const options = {
                expires: new Date(Date.now() + 3 * 24 * 60 * 60 * 1000),
                httpOnly: true,
            };
            res.cookie("token", token, options).status(200).json({
                success: true,
                token,
                user,
                message: `User Loggedin Successfully`,
            });
        } else {
            return res.status(401).json({
                success: false,
                message: `Password is Incorrect`,
            });
        }
    } catch (error) {
        return res.status(500).json({
            success: false,
            message: `Login Failure Please Try Again`,
        });
    }
};

exports.googleAuth = async (req, res, next) => {
    const code = req.body.token;
    try {
        const googleRes = await oauth2Client.getToken(code);
        oauth2Client.setCredentials(googleRes.tokens);
        const userRes = await axios.get(
            `https://www.googleapis.com/oauth2/v1/userinfo?alt=json&access_token=${googleRes.tokens.access_token}`
        );
        const { email, name, picture } = userRes.data;
        let user = await User.findOne({ email });

        if (!user) {
            const profileDetails = await Profile.create({
                gender: null,
                dateOfBirth: null,
                about: null,
                contactNumber: null,
            });
            user = await User.create({
                name,
                email,
                accountType: "Student",
                additionalDetails: profileDetails._id,              
                image: picture,
            });
        }
        const { _id } = user;
      
        const token = jwt.sign(
            { email: user.email, id: user._id, accountType: user.accountType },
            process.env.JWT_SECRET,
            {
                expiresIn: "24h",
            }
        );
        const options = {
            expires: new Date(Date.now() + 3 * 24 * 60 * 60 * 1000),
            httpOnly: true,
        };
        res.cookie("token", token, options).status(200).json({
            success: true,
            token,
            user,
            message: `User Loggedin Successfully`,
        });
    } catch (err) {
        return res.status(500).json({
            success: false,
            message: `Login Failure Please Try Again`,
        });
    }
};
