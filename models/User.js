const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
    id: { type: Number, required: true }, // Keeping numeric ID for backward compatibility
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    key_code: { type: String, required: true },
    hwid: { type: String, default: null },
    hwid_registered_at: { type: Date, default: null },
    registered_ip: { type: String, default: null },
    ip_registered_at: { type: Date, default: null },
    blacklisted: { type: Boolean, default: false },
    blacklist_reason: { type: String, default: null },
    discord_id: { type: String, default: null },
    discord_avatar: { type: String, default: null },
    avatar_base64: { type: String, default: "" },
    created_at: { type: Date, default: Date.now },
    last_login: { type: Date, default: Date.now }
});

module.exports = mongoose.model('User', UserSchema);
