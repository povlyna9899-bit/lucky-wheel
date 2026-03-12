const settingSchema = new mongoose.Schema({
  zero: { type: Number, default: 0 },
  five: { type: Number, default: 0 },
  ten: { type: Number, default: 0 },
  twenty: { type: Number, default: 0 },
  fifty: { type: Number, default: 0 },
  hundred: { type: Number, default: 0 }
});
