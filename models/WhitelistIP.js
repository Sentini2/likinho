const mongoose = require('mongoose');

const whitelistSchema = new mongoose.Schema({
    ip: { type: String, required: true, unique: true },
    addedAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('WhitelistIP', whitelistSchema);
