const mongoose = require('mongoose');

const SettingSchema = new mongoose.Schema({
    key: { type: String, required: true, unique: true }, // e.g., 'main'
    hwid_enabled: { type: Boolean, default: true },
    ip_enabled: { type: Boolean, default: true },
    block_inject: { type: Boolean, default: false },
    locked: { type: Boolean, default: false }, // For chat lock
    current_version: { type: String, default: "1.0" },
    update_url: { type: String, default: "" },
    block_hard: { type: Boolean, default: false },
    block_hard_msg: { type: String, default: "Blocked by Administrator." }
});

module.exports = mongoose.model('Setting', SettingSchema);
