const express = require("express")
const router = express.Router()

const {
    login,
    signup,
    googleAuth
} = require("../controllers/Auth")

router.post("/login", login)

router.post("/signup", signup)

router.post("/google", googleAuth);
module.exports = router;


