const mongoose = require('mongoose');

const MessageSchema = new mongoose.Schema({
  user:     { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  username: { type: String },
  avatar:   { type: String },
  text:     { type: String, required: true },
  createdAt:{ type: Date, default: Date.now }
});

module.exports = mongoose.model('Message', MessageSchema);