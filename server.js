require("dotenv").config();

const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const app = express();
app.use(express.json());
app.use(cors({
  origin: [
     "http://localhost:3000",
    "https://expense-manager-tau-nine.vercel.app"
  ],
  credentials: true
}));

/* ==============================
   MongoDB Connection
============================== */

mongoose.connect(
  process.env.MONGO_URI || "mongodb://127.0.0.1:27017/expense-manager"
)
.then(() => console.log("MongoDB Connected ✅"))
.catch((err) => console.log("MongoDB Error:", err));
/* ==============================
   User Schema
============================== */

const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true }
}, { timestamps: true });

const User = mongoose.model("User", userSchema);

/* ==============================
   Expense Schema
============================== */

const expenseSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  title: { type: String, required: true },
  amount: { type: Number, required: true },
  category: { type: String, required: true }
}, { timestamps: true });

const Expense = mongoose.model("Expense", expenseSchema);

/* ==============================
   Auth Middleware
============================== */

const authMiddleware = (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader) {
      return res.status(401).json({ message: "No token provided" });
    }

    const token = authHeader.split(" ")[1];

    const decoded = jwt.verify(token, process.env.JWT_SECRET || "secretkey");

    req.user = decoded;
    next();

  } catch (error) {
    return res.status(401).json({ message: "Invalid or expired token" });
  }
};

/* ==============================
   Register
============================== */

app.post("/api/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password)
      return res.status(400).json({ message: "All fields are required" });

    const existingUser = await User.findOne({ email });
    if (existingUser)
      return res.status(400).json({ message: "User already exists" });

    const hashedPassword = await bcrypt.hash(password, 10);

    await User.create({ name, email, password: hashedPassword });

    res.status(201).json({ message: "User registered successfully 🎉" });

  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Server error" });
  }
});

/* ==============================
   Login
============================== */

app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password)
      return res.status(400).json({ message: "All fields are required" });

    const user = await User.findOne({ email });
    if (!user)
      return res.status(400).json({ message: "Invalid email or password" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch)
      return res.status(400).json({ message: "Invalid email or password" });

    const token = jwt.sign(
      { id: user._id },
      process.env.JWT_SECRET || "secretkey",
      { expiresIn: "1h" }
    );

    res.status(200).json({
      message: "Login successful ✅",
      token
    });

  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Server error" });
  }
});

/* ==============================
   Profile (Protected)
============================== */

app.get("/api/profile", authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select("-password");

    res.status(200).json({
      message: "Profile fetched successfully 🔐",
      user
    });

  } catch (error) {
    res.status(500).json({ message: "Server error" });
  }
});

/* ==============================
   Add Expense
============================== */

app.post("/api/expenses", authMiddleware, async (req, res) => {
  try {
    const { title, amount, category } = req.body;

    if (!title || !amount || !category)
      return res.status(400).json({ message: "All fields are required" });

    const newExpense = await Expense.create({
      user: req.user.id,
      title,
      amount,
      category
    });

    res.status(201).json({
      message: "Expense added successfully 💰",
      expense: newExpense
    });

  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Server error" });
  }
});

/* ==============================
   Get All Expenses
============================== */

app.get("/api/expenses", authMiddleware, async (req, res) => {
  try {
    const expenses = await Expense.find({ user: req.user.id })
      .sort({ createdAt: -1 });

    res.status(200).json({
      message: "Expenses fetched successfully 📥",
      count: expenses.length,
      expenses
    });

  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Server error" });
  }
});

/* ==============================
   Update Expense
============================== */

app.put("/api/expenses/:id", authMiddleware, async (req, res) => {
  try {
    const expense = await Expense.findOne({
      _id: req.params.id,
      user: req.user.id
    });

    if (!expense)
      return res.status(404).json({ message: "Expense not found" });

    expense.title = req.body.title || expense.title;
    expense.amount = req.body.amount || expense.amount;
    expense.category = req.body.category || expense.category;

    await expense.save();

    res.status(200).json({
      message: "Expense updated successfully ✏️",
      expense
    });

  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Server error" });
  }
});

/* ==============================
   Delete Expense
============================== */

app.delete("/api/expenses/:id", authMiddleware, async (req, res) => {
  try {
    const expense = await Expense.findOneAndDelete({
      _id: req.params.id,
      user: req.user.id
    });

    if (!expense)
      return res.status(404).json({ message: "Expense not found" });

    res.status(200).json({
      message: "Expense deleted successfully 🗑"
    });

  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Server error" });
  }
});

/* ==============================
   Start Server
============================== */

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT} 🚀`);
});
