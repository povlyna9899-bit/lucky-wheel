require("dotenv").config();

const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const path = require("path");

const app = express();

/* ===================== CONNECT MONGODB ===================== */

mongoose.connect(process.env.MONGO_URI)
.then(async()=>{

 console.log("✅ MongoDB Connected");

 await createSuperAdmin();

})
.catch(err=>console.log("❌ Mongo Error:",err));


/* ===================== MIDDLEWARE ===================== */

app.use(express.json());
app.use(express.static(path.join(__dirname,"public")));


/* ===================== MODELS ===================== */

const userSchema = new mongoose.Schema({

  username:{
    type:String,
    unique:true,
    required:true
  },

  password:{
    type:String,
    required:true
  },

  role:{
    type:String,
    enum:["superadmin","admin","player"],
    default:"player"
  },

  prefix:String,

  parentAdmin:String,

  spinsLeft:{
    type:Number,
    default:0
  },

  balance:{
    type:Number,
    default:0
  }

});

const User = mongoose.model("User",userSchema);


const spinSchema = new mongoose.Schema({

  userId:{
    type:mongoose.Schema.Types.ObjectId,
    ref:"User"
  },

  username:String,

  prize:Number,

  prizeLabel:String,

  createdAt:{
    type:Date,
    default:Date.now
  }

});

const Spin = mongoose.model("Spin",spinSchema);

// AUTO CREATE SUPERADMIN
async function createSuperAdmin(){

 const exist = await User.findOne({role:"superadmin"});

 if(!exist){

  const hash = await bcrypt.hash("admin123",10);

  await User.create({
   username:"admin",
   password:hash,
   role:"superadmin",
   prefix:"CBPAABCC"
  });

  console.log("✅ Superadmin created");
 }

}
/* ===================== PRIZE SETTINGS ===================== */

const prizeSettingSchema = new mongoose.Schema({

  values:{
    type:Map,
    of:Number
  }

});

const PrizeSetting = mongoose.model("PrizeSetting",prizeSettingSchema);

/* ===================== GET PRIZE SETTINGS ===================== */

app.get("/api/admin/prize-settings", verifyToken, async (req,res)=>{

if(req.user.role!=="admin" && req.user.role!=="superadmin")
return res.status(403).json({message:"Admin only"});

let setting = await PrizeSetting.findOne();

if(!setting){

setting = await PrizeSetting.create({

values:{
0:50,
5:10,
10:10,
20:10,
30:10,
50:5,
100:4,
200:1
}

});

}

const valuesObject = Object.fromEntries(setting.values);

const result = Object.entries(valuesObject).map(([v,w])=>({
value:Number(v),
weight:Number(w)
}));

res.json(result);

});


/* ===================== SAVE PRIZE SETTINGS ===================== */

app.post("/api/admin/prize-settings", verifyToken, async (req,res)=>{

if(req.user.role!=="admin" && req.user.role!=="superadmin")
return res.status(403).json({message:"Admin only"});

const prizes = req.body;

const valuesObject = {};

prizes.forEach(p=>{
valuesObject[p.value] = Number(p.weight);
});

await PrizeSetting.findOneAndUpdate(
{},
{values:valuesObject},
{upsert:true}
);

res.json({success:true});

});
/* ===================== VERIFY TOKEN ===================== */

function verifyToken(req,res,next){

  const authHeader = req.headers.authorization;

  if(!authHeader)
  return res.status(401).json({message:"No token"});

  const token = authHeader.split(" ")[1];

  try{

    const decoded = jwt.verify(token,process.env.JWT_SECRET);

    req.user = decoded;

    next();

  }catch{

    res.status(403).json({message:"Invalid token"});

  }

}


/* ===================== ADMIN LOGIN ===================== */

app.post("/admin-login",async(req,res)=>{

try{

const {username,password} = req.body;

const admin = await User.findOne({
username,
role:{$in:["superadmin","admin"]}
});

if(!admin)
return res.json({success:false,message:"Wrong Admin"});

const valid = await bcrypt.compare(password,admin.password);

if(!valid)
return res.json({success:false,message:"Wrong Admin"});

const token = jwt.sign({

id:admin._id,
username:admin.username,
role:admin.role,
prefix:admin.prefix

},process.env.JWT_SECRET,{expiresIn:"2h"});

res.json({
success:true,
token,
role:admin.role,
prefix:admin.prefix
});

}catch(err){

console.log(err);
res.status(500).json({success:false});

}

});


/* ===================== PLAYER LOGIN ===================== */

app.post("/player/login",async(req,res)=>{

const {username,password} = req.body;

const user = await User.findOne({
username,
role:"player"
});

if(!user)
return res.json({success:false});

const valid = await bcrypt.compare(password,user.password);

if(!valid)
return res.json({success:false});

const token = jwt.sign({

id:user._id,
username:user.username,
role:"player"

},process.env.JWT_SECRET,{expiresIn:"2h"});

res.json({success:true,token});

});


/* ===================== CREATE ADMIN ===================== */

app.post("/create-admin",verifyToken,async(req,res)=>{

if(req.user.role!=="superadmin")
return res.status(403).json({message:"Superadmin only"});

const {username,password,prefix} = req.body;

const exist = await User.findOne({username});

if(exist)
return res.json({success:false,message:"User exists"});

const hash = await bcrypt.hash(password,10);

await User.create({

username,
password:hash,
role:"admin",
prefix

});

res.json({success:true});

});


/* ===================== GET ADMINS ===================== */

app.get("/admins",verifyToken,async(req,res)=>{

if(req.user.role!=="superadmin")
return res.status(403).json({message:"Superadmin only"});

const admins = await User.find(
{role:"admin"},
"-password"
);

res.json(admins);

});


/* ===================== DELETE ADMIN ===================== */

app.delete("/delete-admin/:id",verifyToken,async(req,res)=>{

if(req.user.role!=="superadmin")
return res.status(403).json({message:"Superadmin only"});

await User.findByIdAndDelete(req.params.id);

res.json({success:true});

});
/* ===================== EDIT ADMIN ===================== */

app.put("/edit-admin/:id", verifyToken, async (req,res)=>{

if(req.user.role !== "superadmin")
return res.status(403).json({message:"Superadmin only"});

const {password} = req.body;

if(!password)
return res.json({success:false,message:"Password required"});

const hash = await bcrypt.hash(password,10);

await User.findByIdAndUpdate(req.params.id,{
password:hash
});

res.json({success:true});

});

/* ===================== CREATE PLAYER ===================== */

app.post("/create-player",verifyToken,async(req,res)=>{

if(req.user.role!=="admin" && req.user.role!=="superadmin")
return res.status(403).json({message:"Admin only"});

const {username,password} = req.body;

const exist = await User.findOne({username});

if(exist)
return res.json({success:false});

const hash = await bcrypt.hash(password,10);

await User.create({

username,
password:hash,
role:"player",
parentAdmin:req.user.username

});

res.json({success:true});

});


/* ===================== GET PLAYERS ===================== */

app.get("/players",verifyToken,async(req,res)=>{

if(req.user.role!=="admin" && req.user.role!=="superadmin")
return res.status(403).json({message:"Admin only"});

const users = await User.find({

role:"player",
parentAdmin:req.user.username

},"-password");

res.json(users);

});

/* ===================== EDIT PLAYER ===================== */

app.put("/edit-player/:id", verifyToken, async (req,res)=>{

if(req.user.role!=="admin" && req.user.role!=="superadmin")
return res.status(403).json({message:"Admin only"});

const {username,password} = req.body;

const update = {};

if(username) update.username = username;

if(password){
const hash = await bcrypt.hash(password,10);
update.password = hash;
}

await User.findByIdAndUpdate(req.params.id,update);

res.json({success:true});

});


/* ===================== DELETE PLAYER ===================== */

app.delete("/delete/:id", verifyToken, async (req,res)=>{

if(req.user.role!=="admin" && req.user.role!=="superadmin")
return res.status(403).json({message:"Admin only"});

await User.findByIdAndDelete(req.params.id);

res.json({success:true});

});


/* ===================== SET SPIN ===================== */

app.put("/set-spin/:id", verifyToken, async (req,res)=>{

if(req.user.role!=="admin" && req.user.role!=="superadmin")
return res.status(403).json({message:"Admin only"});

const {spins} = req.body;

await User.findByIdAndUpdate(req.params.id,{
spinsLeft:Number(spins)
});

res.json({success:true});

});


/* ===================== USER HISTORY ===================== */

app.get("/api/admin/user-history/:userId", verifyToken, async (req,res)=>{

const spins = await Spin.find({
userId:req.params.userId
}).sort({createdAt:-1});

res.json(spins);

});


/* ===================== DELETE SPIN HISTORY ===================== */

app.delete("/admin/clear-history/:id", verifyToken, async (req,res)=>{

await Spin.findByIdAndDelete(req.params.id);

res.json({success:true});

});
/* ===================== PLAYER SPIN ===================== */

app.post("/spin",verifyToken,async(req,res)=>{

if(req.user.role!=="player")
return res.status(403).json({message:"Player only"});

const user = await User.findById(req.user.id);

if(!user)
return res.status(404).json({message:"User not found"});

if(user.spinsLeft<=0)
return res.status(400).json({message:"No spins"});


let setting = await PrizeSetting.findOne();

if(!setting){

setting = await PrizeSetting.create({

values:{
0:50,
5:10,
10:10,
20:10,
30:10,
50:5,
100:4,
200:1
}

});

}

const valuesObject = Object.fromEntries(setting.values);

const prizeConfig = Object.entries(valuesObject).map(([v,w])=>({
value:Number(v),
weight:Number(w)
}));

const totalWeight = prizeConfig.reduce((a,b)=>a+b.weight,0);

const random = Math.random()*totalWeight;

let cumulative=0;
let selectedPrize=0;

for(const item of prizeConfig){

cumulative+=item.weight;

if(random<=cumulative){

selectedPrize=item.value;
break;

}

}

user.spinsLeft -=1;
user.balance += selectedPrize;

if(selectedPrize===50)
user.spinsLeft +=1;

await user.save();

const prizeLabels = {
  0: "អ្នកឈ្នះ1$",
  5: "អ្នកឈ្នះ2$",
  10: "អ្នកឈ្នះ5$",
  20: "អ្នកឈ្នះ50$",
  30: "អ្នកឈ្នះ100$",
  50: "Free 1 Spin",
  100: "Sអ្នកឈ្នះ500$",
  200: "I PHONE 17 Pro Max"
};

await Spin.create({
  userId: user._id,
  username: user.username,
  prize: selectedPrize,
  prizeLabel: prizeLabels[selectedPrize] || ("$"+selectedPrize)
});
res.json({
  prize: selectedPrize,
  spinsLeft: user.spinsLeft,
  balance: user.balance
});
});
/* ===================== MY SPIN INFO ===================== */

app.get("/api/my-spin", verifyToken, async (req,res)=>{

const user = await User.findById(req.user.id);

if(!user)
return res.status(404).json({message:"User not found"});

res.json({

spinsLeft:user.spinsLeft,
balance:user.balance

});

});
/* ===================== MY HISTORY ===================== */

app.get("/api/history", verifyToken, async (req,res)=>{

const spins = await Spin.find({
userId:req.user.id
}).sort({createdAt:-1});

res.json(spins);

});
/* ===================== HTML ROUTES ===================== */

app.get("/",(req,res)=>{
res.sendFile(path.join(__dirname,"public","index.html"));
});

app.get("/admin",(req,res)=>{
res.sendFile(path.join(__dirname,"public","admin.html"));
});

app.get("/player",(req,res)=>{
res.sendFile(path.join(__dirname,"public","player-page.html"));
});


/* ===================== START SERVER ===================== */

const PORT = process.env.PORT || 3000;

app.listen(PORT,()=>{
console.log("🚀 Server running on port "+PORT);
});