const mongoose = require("mongoose");

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
const User = mongoose.model("User", userSchema);
module.exports = mongoose.model("User", userSchema);