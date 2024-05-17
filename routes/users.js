import express from "express";

import { login, signup, forgetPassword, resetPassword } from "../controllers/auth.js";
import { getAllUsers, updateProfile } from "../controllers/users.js";
import auth from "../middleware/auth.js";

const router = express.Router();

router.post("/signup", signup);
router.post("/login", login);

router.post("/forgetPassword", forgetPassword);
router.post("/resetPassword", resetPassword); 

router.get("/getAllUsers", getAllUsers);
router.patch("/update/:id", auth, updateProfile);

export default router;
