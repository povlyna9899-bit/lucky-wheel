require("dotenv").config();

const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const path = require("path");

const app = express();

/* =======================
   CONNECT MONGODB
======================= */
mongoose.connect(process.env.MONGO_URI)
.then(() => console.log("✅ MongoDB Connected"))
.catch(err => console.log("❌ Mongo Error:", err));

/* =======================
   MIDDLEWARE
======================= */
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

/* =======================
   MODELS
======================= */
const userSchema = new mongoose.Schema({
  username: { type:String, unique:true },
  password: String,
  role: { type:String, default:"player" }
});

const spinSchema = new mongoose.Schema({
  userId: String,
  username: String,
  prize: String,
  createdAt: { type:Date, default:Date.now }
});

const User = mongoose.model("User", userSchema);
const Spin = mongoose.model("Spin", spinSchema);

/* =======================
   VERIFY TOKEN
======================= */
function verifyToken(req, res, next) {

  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ message: "No Token" });

  const token = header.split(" ")[1];

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    res.status(403).json({ message: "Invalid Token" });
  }
}

/* =======================
   ADMIN LOGIN
======================= */
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

/* =======================
   PLAYER LOGIN
======================= */
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

/* =======================
   CREATE PLAYER (ADMIN)
======================= */
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

  await User.create({ username, password: hash });

  res.json({ success: true });
});

/* =======================
   GET PLAYERS (ADMIN)
======================= */
app.get("/players", verifyToken, async (req, res) => {

  if (req.user.role !== "admin")
    return res.status(403).json({ message: "Admin Only" });

  const users = await User.find({}, "-password");
  res.json(users);
});

/* =======================
   EDIT PLAYER (ADMIN)
======================= */
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

/* =======================
   DELETE PLAYER (ADMIN)
======================= */
app.delete("/delete/:id", verifyToken, async (req, res) => {

  if (req.user.role !== "admin")
    return res.status(403).json({ message: "Admin Only" });

  await User.findByIdAndDelete(req.params.id);

  res.json({ success: true });
});

/* =======================
   SPIN GAME (PLAYER)
======================= */

const prizes = [
  "💎 10 Points",
  "💎 20 Points",
  "💰 50 Points",
  "🎁 Bonus",
  "🔥 Jackpot",
  "❌ Try Again"
];

app.post("/api/spin", verifyToken, async (req, res) => {

  if (req.user.role !== "player")
    return res.status(403).json({ message: "Player Only" });

  // Daily limit (1 spin per day)
  const today = new Date();
  today.setHours(0,0,0,0);

  const alreadySpun = await Spin.findOne({
    userId: req.user.id,
    createdAt: { $gte: today }
  });

  if (alreadySpun) {
    return res.json({
      success: false,
      message: "You already spun today!"
    });
  }

  const prize = prizes[Math.floor(Math.random() * prizes.length)];

  await Spin.create({
    userId: req.user.id,
    username: req.user.username,
    prize
  });

  res.json({ success: true, prize });
});

/* =======================
   ADMIN SEE ALL SPINS
======================= */
app.get("/api/spins", verifyToken, async (req, res) => {

  if (req.user.role !== "admin")
    return res.status(403).json({ message: "Admin Only" });

  const spins = await Spin.find().sort({ createdAt: -1 });
  res.json(spins);
});

/* =======================
   LEADERBOARD
======================= */
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

/* =======================
   ROUTE HISTORY
======================= */
app.get("/api/history/:username", async (req,res)=>{
  const spins = await Spin.find({ username:req.params.username });
  res.json(spins);
});

/* =======================
   HTML ROUTES
======================= */
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.get("/admin", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "admin.html"));
});

app.get("/player", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "player-page.html"));
});

/* =======================
   START SERVER
======================= */
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log("🚀 Server running on port " + PORT);
});