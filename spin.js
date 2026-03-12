const mongoose = require("mongoose");

const spinSchema = new mongoose.Schema({
  username: String,
  prize: String,
  date: {
    type: Date,
    default: Date.now
  }
});

module.exports = mongoose.model("Spin", spinSchema);