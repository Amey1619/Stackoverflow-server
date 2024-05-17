import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import users from "../models/auth.js";
import nodemailer from "nodemailer";
import dotenv from "dotenv";

dotenv.config();

export const signup = async (req, res) => {
  const { name, email, password } = req.body;
  try {
    const existinguser = await users.findOne({ email });
    if (existinguser) {
      return res.status(404).json({ message: "User already Exist." });
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    const newUser = await users.create({
      name,
      email,
      password: hashedPassword,
    });
    const token = jwt.sign(
      { email: newUser.email, id: newUser._id },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );
    res.status(200).json({ result: newUser, token });
  } catch (error) {
    res.status(500).json("Something went worng...");
  }
};

export const login = async (req, res) => {
  const { email, password } = req.body;
  try {
    const existinguser = await users.findOne({ email });
    if (!existinguser) {
      return res.status(404).json({ message: "User don't Exist." });
    }
    const isPasswordCrt = await bcrypt.compare(password, existinguser.password);
    if (!isPasswordCrt) {
      return res.status(400).json({ message: "Invalid credentials" });
    }
    const token = jwt.sign(
      { email: existinguser.email, id: existinguser._id },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );
    res.status(200).json({ result: existinguser, token });
  } catch (error) {
    res.status(500).json("Something went worng...");
  }
};

export const forgetPassword = async (req, res) => {
  const { email } = req.body;
  try {
    const existinguser = await users.findOne({ email });
    if (!existinguser) {
      return res.status(404).json({ message: "User not found" });
    }
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpExpires = new Date(Date.now() + 15 * 60 * 1000);
    existinguser.resetPasswordOTP = otp;
    existinguser.resetPasswordOTPExpires = otpExpires;
    await existinguser.save();

    const transporter = nodemailer.createTransport({
    service: 'gmail',
    host: "smtp.gmail.com",
    port: 587, 
    secure: false,
    auth: {
      user: process.env.EMAIL,
      pass: process.env.APP_PASS,
      }
    });

    const mailOptions = {
      from:{
        name:'NullClass',
        address:process.env.EMAIL,
      },
      to: email,
      subject: "Reset Your Password", 
      text: `Your One-Time-Password is ${otp}.`,
    };
    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.log(error);
        return res.status(500).json({ message: "Failed to send OTP" });
      } else {
        console.log(`Email sent: ` + info.response);
        return res
          .status(200)
          .json({ message: `OTP sent successfully to your ${email}` });
      }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Something went wrong." });
  }
};

export const resetPassword = async (req, res) => {
  const { email, otp, newPassword } = req.body;
  try {
    const existinguser = await users.findOne({ email });
    if (!existinguser) {
      return res.status(404).json({ message: "User not found." });
    }
    if (existinguser.resetPasswordOTP !== otp) {
      return res.status(400).json({ message: "Invalid OTP" });
    }
    if (existinguser.resetPasswordOTPExpires < new Date()) {
      return res.status(400).json({ message: "OTP expired" });
    }
    const hashedPassword = await bcrypt.hash(newPassword, 12);
    existinguser.password = hashedPassword;
    existinguser.resetPasswordOTP = null;
    existinguser.resetPasswordOTPExpires = null;
    await existinguser.save();
    res.status(200).json({ message: "Password reset successfully." });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Something went wrong." });
  }
};