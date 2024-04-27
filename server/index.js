const express = require("express");
const dotEnv = require("dotenv");
const cors = require("cors");

const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
app.use(express.json());
// Allow requests from all origins during development
app.use(cors());

dotEnv.config();
const secretKey = process.env.JWT_SECRET_KEY;

const User = require("./models/User");

//mongodb connection
mongoose
  .connect(process.env.MONGO_URL)
  .then((res) => console.log("Mongodb connected Successfully"))
  .catch((err) => console.log(err, "err"));


// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
  const token = req.header("Authorization");

  // Check if the token is missing
  if (!token) {
    return res.status(401).json({ message: "Authentication token is missing" });
  }

  // Check if the token format is incorrect (missing "Bearer" prefix)
  if (!token.startsWith("Bearer ")) {
    return res.status(401).json({ message: "Invalid token format" });
  }

  // Extract the token without the "Bearer" prefix
  const tokenWithoutBearer = token.slice(7);

  // Verify the token and check its expiration
  jwt.verify(tokenWithoutBearer, process.env.JWT_SECRET_KEY, (err, decoded) => {
    if (err) {
      if (err.name === "TokenExpiredError") {
        return res.status(401).json({ message: "Token has expired" });
      } else {
        return res.status(403).json({ message: "Invalid token" });
      }
    }

    // Token is valid, and you can access its payload in `decoded`
    req.user = decoded;
    next();
  });
};


// Routes
//signup api
app.post("/signup", async (req, res) => {
  try {
    const { name, email, mobileNum, password } = req.body;
    console.log("credentials------", name, email, mobileNum, password);

    // Check if required fields are provided
    if (!name || !email || !mobileNum || !password) {
      return res
        .status(400)
        .json({ message: "Please provide all required fields" });
    }

    // Validate email format using regular expression
    const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ message: "Invalid email format" });
    }

    // Check if the email is already registered
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({
        message: "Email already exists, please use a different email",
      });
    }

    // Validate mobile number format (e.g., 10 digits)
    if (!/^\d{10}$/.test(mobileNum)) {
      return res
        .status(400)
        .json({ message: "Mobile number must be 10 digits" });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create a new user instance
    const newUser = new User({
      name,
      email,
      mobileNum,
      password: hashedPassword,
    });
    console.log("newUser---", newUser);

    // Save the user to the database
    await newUser.save();

    res.status(201).json({ message: "User registered successfully" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

//login api
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  console.log("user provided credentials", email, password);
  try {
    if (!email || !password) {
      return res
        .status(400)
        .json({ message: "Enter valid email and password" });
    }

    const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ message: "Enter valid email" });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: "Incorrect password" });
    }

    // Generate JWT token
    const token = jwt.sign({ email: user.email }, secretKey, {
      expiresIn: "10h",
    });
    res.json({ token, id: user._id });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Internal server error" });
  }
});

//get user details
app.get("/user/:id", authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.params.id).select("-password");
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }
    res.json(user);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


//get all users data
app.get("/allusers", authenticateToken, async (req, res) => {
  try {
    // Fetch all users from the User model (excluding password field)
    const users = await User.find().select("-password");
    res.json(users);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});



const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`Server Started and running at ${PORT}`);
});
