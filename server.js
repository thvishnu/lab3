const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const upload = require("./config/multer");
const UserModel = require("./models/User");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
require("dotenv").config();

const GMAIL_USER = process.env.EMAIL_USER;
const GMAIL_PASS = process.env.EMAIL_PASS;

const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    },
});

const generateOtp = () =>
    Math.floor(100000 + Math.random() * 900000).toString();

const sendOtpEmail = async (email, otp) => {
    await transporter.sendMail({
        from: GMAIL_USER,
        to: email,
        subject: "Your OTP Code",
        text: `Your OTP code is: ${otp}`,
    });
};

const PORT = process.env.PORT || 3005;
const app = express();
app.use(express.json());

mongoose
    .connect(
        process.env.MONGO_URI,
    )
    .then(() => {
        app.listen(PORT, () => {
            console.log(`Server is running on port ${PORT}`);
        });
    });

app.post("/api/register", upload.single("image"), async (req, res) => {
    try {
        const { name, email, password } = req.body;
        const image = req.file;
        const hashedPassword = await bcrypt.hash(password, 10);
        upload(image, async (err, result) => {
            if (err) {
                return res
                    .status(500)
                    .json({ message: "Error uploading image" });
            }
            const otp = generateOtp();
            const user = new UserModel({
                name,
                email,
                password: hashedPassword,
                image: result,
                otp,
            });
            await user.save();
            await sendOtpEmail(email, otp);
            const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
                expiresIn: "1h",
            });
            res.json({
                message: "User registered successfully. OTP sent to email.",
                token: token,
                user: user,
            });
        });
    } catch (error) {
        res.status(500).json({ message: "Error registering user" });
    }
});

app.post("/api/login", async (req, res) => {
    try {
        const { email, password } = req.body;

        const user = await UserModel.findOne({ email });
        if (!user) {
            return res.status(401).json({ message: "Invalid credentials" });
        }
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ message: "Invalid credentials" });
        }
        const otp = generateOtp();
        user.otp = otp;
        await user.save();
        await sendOtpEmail(user.email, otp);
        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
            expiresIn: "1h",
        });
        res.json({ message: "Login successful. OTP sent to email.", token: token, user: user });
    } catch (error) {
        res.status(500).json({ message: "Error logging in" });
    }
});

const verify = (req, res, next) => {
    const token = req.header("Authorization");
    if (!token) {
        return res
            .status(401)
            .json({ message: "No token, authorization denied" });
    }
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        res.status(401).json({ message: "Token is not valid" });
    }
};

app.get("/api/auth/me", verify, async (req, res) => {
    try {
        const token = req.header("Authorization");
        if (!token) {
            return res.status(404).json({ message: "User not found" });
        }
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const userId = decoded.id;
        const user = await UserModel.findById(userId);
        res.json({ user: user, token: token });
    } catch (error) {
        res.status(500).json({ message: "Error getting user" });
    }
});

app.get("/api/users", verify, async (req, res) => {
    try {
        const users = await UserModel.find();
        res.json({ users: users });
    } catch (error) {
        res.status(500).json({ message: "Error getting users" });
    }
});

app.get("/api/users/:id", verify, async (req, res) => {
    try {
        const user = await UserModel.findById(req.params.id);
        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }
        res.json({ user: user });
    } catch (error) {
        res.status(500).json({ message: "Error getting user" });
    }
});

app.put("/api/users/:id", verify, async (req, res) => {
    try {
        const user = await UserModel.findByIdAndUpdate(
            req.params.id,
            req.body,
            { new: true },
        );
        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }
        res.json({ user: user });
    } catch (error) {
        res.status(500).json({ message: "Error updating user" });
    }
});

app.delete("/api/users/:id", verify, async (req, res) => {
    try {
        const user = await UserModel.findByIdAndDelete(req.params.id);
        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }
        res.json({ message: "User deleted" });
    } catch (error) {
        res.status(500).json({ message: "Error deleting user" });
    }
});

app.post("/api/users/upload-profile", verify, async (req, res) => {
    try {
        const { file } = req;
        if (!file) {
            return res.status(400).json({ message: "No file uploaded" });
        }

        res.json({ message: "Profile uploaded" });
    } catch (error) {
        res.status(500).json({ message: "Error uploading profile" });
    }
});
