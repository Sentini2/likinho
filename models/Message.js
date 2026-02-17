const mongoose = require('mongoose');

const MessageSchema = new mongoose.Schema({
    username: { type: String, required: true },
    text: { type: String, required: true },
    role: { type: String, default: 'user' }, // 'user' or 'admin'
    avatar: { type: String, default: '' },
    timestamp: { type: Number, default: Date.now },
    created_at: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Message', MessageSchema);
