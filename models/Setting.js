const mongoose = require('mongoose');

const SettingSchema = new mongoose.Schema({
    key: { type: String, required: true, unique: true }, // e.g., 'main'
    hwid_enabled: { type: Boolean, default: true },
    ip_enabled: { type: Boolean, default: true },
    block_inject: { type: Boolean, default: false },
    locked: { type: Boolean, default: false } // For chat lock
});

module.exports = mongoose.model('Setting', SettingSchema);
