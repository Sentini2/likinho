const mongoose = require('mongoose');

const UpdateHistorySchema = new mongoose.Schema({
    version: { type: String, required: true },
    url: { type: String, required: true },
    date: { type: Date, default: Date.now }
});

module.exports = mongoose.model('UpdateHistory', UpdateHistorySchema);
