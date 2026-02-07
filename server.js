require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const path = require("path");

const app = express();

/* ===================== CONNECT MONGODB ===================== */
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("✅ MongoDB Connected"))
  .catch(err => console.log("❌ Mongo Error:", err));

/* ===================== MIDDLEWARE ===================== */
app.use(express.json());
app.use(express.static(__dirname)); // ✅ FIXED (no public folder)

/* ===================== MODELS ===================== */
const userSchema = new mongoose.Schema({
  username: { type: String, unique: true },
  password: String,
  role: { type: String, default: "player" },
  spinsLeft: { type: Number, default: 0 },
  balance: { type: Number, default: 0 }
});

const spinSchema = new mongoose.Schema({
  userId: String,
  username: String,
  prize: Number,
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model("User", userSchema);
const Spin = mongoose.model("Spin", spinSchema);

/* ===================== VERIFY TOKEN ===================== */
function verifyToken(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader)
    return res.status(401).json({ message: "No token provided" });

  const token = authHeader.split(" ")[1];
  if (!token)
    return res.status(401).json({ message: "Invalid token format" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    return res.status(403).json({ message: "Invalid or expired token" });
  }
}

/* ===================== ADMIN LOGIN ===================== */
app.post("/admin-login", (req, res) => {
  const { username, password } = req.body;

  if (
    username === process.env.ADMIN_USER &&
    password === process.env.ADMIN_PASS
  ) {
    const token = jwt.sign(
      { role: "admin" },
      process.env.JWT_SECRET,
      { expiresIn: "2h" }
    );
    return res.json({ success: true, token });
  }

  res.json({ success: false, message: "Wrong Admin" });
});

/* ===================== PLAYER LOGIN ===================== */
app.post("/player/login", async (req, res) => {
  const { username, password } = req.body;

  const user = await User.findOne({ username });
  if (!user) return res.json({ success: false });

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.json({ success: false });

  const token = jwt.sign(
    { id: user._id, role: "player", username: user.username },
    process.env.JWT_SECRET,
    { expiresIn: "2h" }
  );

  res.json({ success: true, token });
});

/* ===================== CREATE PLAYER ===================== */
app.post("/create-player", verifyToken, async (req, res) => {
  if (req.user.role !== "admin")
    return res.status(403).json({ message: "Admin Only" });

  const { username, password } = req.body;

  if (!username || !password)
    return res.json({ success: false, message: "Missing fields" });

  const exist = await User.findOne({ username });
  if (exist)
    return res.json({ success: false, message: "User exists" });

  const hash = await bcrypt.hash(password, 10);

  await User.create({
    username,
    password: hash,
    role: "player"
  });

  res.json({ success: true });
});

/* ===================== GET PLAYERS ===================== */
app.get("/players", verifyToken, async (req, res) => {
  if (req.user.role !== "admin")
    return res.status(403).json({ message: "Admin Only" });

  const users = await User.find({}, "-password");
  res.json(users);
});

/* ===================== EDIT PLAYER ===================== */
app.put("/edit-player/:id", verifyToken, async (req, res) => {
  if (req.user.role !== "admin")
    return res.status(403).json({ message: "Admin Only" });

  const { username, password } = req.body;
  const updateData = {};

  if (username) updateData.username = username;

  if (password) {
    const hash = await bcrypt.hash(password, 10);
    updateData.password = hash;
  }

  await User.findByIdAndUpdate(req.params.id, updateData);
  res.json({ success: true });
});

/* ===================== SET SPIN ===================== */
app.put("/set-spin/:id", verifyToken, async (req, res) => {
  if (req.user.role !== "admin")
    return res.status(403).json({ message: "Admin Only" });

  const { spins } = req.body;
  if (spins == null)
    return res.json({ success: false, message: "Missing spins value" });

  await User.findByIdAndUpdate(req.params.id, {
    spinsLeft: Number(spins)
  });

  res.json({ success: true });
});

/* ===================== DELETE PLAYER ===================== */
app.delete("/delete/:id", verifyToken, async (req, res) => {
  if (req.user.role !== "admin")
    return res.status(403).json({ message: "Admin Only" });

  await User.findByIdAndDelete(req.params.id);
  res.json({ success: true });
});

/* ===================== ADMIN USER HISTORY ===================== */
app.get("/api/admin/user-history/:userId", verifyToken, async (req, res) => {
  if (req.user.role !== "admin")
    return res.status(403).json({ message: "Admin Only" });

  const { start, end } = req.query;
  let filter = { userId: req.params.userId };

  if (start && end) {
    filter.createdAt = {
      $gte: new Date(start),
      $lte: new Date(end)
    };
  }

  const spins = await Spin.find(filter).sort({ createdAt: -1 });
  res.json(spins);
});

/* ===================== PLAYER SPIN ===================== */
app.post("/spin", verifyToken, async (req, res) => {
  if (req.user.role !== "player")
    return res.status(403).json({ message: "Player Only" });

  const user = await User.findById(req.user.id);
  if (!user)
    return res.status(404).json({ message: "User not found" });

  if (user.spinsLeft <= 0)
    return res.status(400).json({ message: "No spins remaining" });

  const prizes = [0, 5, 10, 20, 30, 50, 100];
  const randomPrize =
    prizes[Math.floor(Math.random() * prizes.length)];

  user.spinsLeft -= 1;
  user.balance += randomPrize;

  await user.save();

  await Spin.create({
    userId: user._id,
    username: user.username,
    prize: randomPrize
  });

  res.json({
    prize: randomPrize,
    spinsLeft: user.spinsLeft,
    balance: user.balance
  });
});

/* ===================== MY SPIN INFO ===================== */
app.get("/api/my-spin", verifyToken, async (req, res) => {
  const user = await User.findById(req.user.id);
  if (!user)
    return res.status(404).json({ message: "User not found" });

  res.json({
    spinsLeft: user.spinsLeft,
    balance: user.balance
  });
});

/* ===================== MY HISTORY ===================== */
app.get("/api/history", verifyToken, async (req, res) => {
  const spins = await Spin.find({ userId: req.user.id })
    .sort({ createdAt: -1 });

  res.json(spins);
});

/* ===================== ADMIN SEE ALL SPINS ===================== */
app.get("/api/spins", verifyToken, async (req, res) => {
  if (req.user.role !== "admin")
    return res.status(403).json({ message: "Admin Only" });

  const spins = await Spin.find().sort({ createdAt: -1 });
  res.json(spins);
});

/* ===================== LEADERBOARD ===================== */
app.get("/api/leaderboard", async (req, res) => {
  const leaderboard = await Spin.aggregate([
    {
      $group: {
        _id: "$username",
        totalSpins: { $sum: 1 }
      }
    },
    { $sort: { totalSpins: -1 } }
  ]);

  res.json(leaderboard);
});

/* ===================== HTML ROUTES ===================== */
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

app.get("/admin", (req, res) => {
  res.sendFile(path.join(__dirname, "admin.html"));
});

app.get("/player", (req, res) => {
  res.sendFile(path.join(__dirname, "player-page.html"));
});

/* ===================== START SERVER ===================== */
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log("🚀 Server running on port " + PORT);
});