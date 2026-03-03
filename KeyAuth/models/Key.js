const mongoose = require('mongoose');

const KeySchema = new mongoose.Schema({
    id: { type: Number, required: true },
    key_code: { type: String, required: true, unique: true },
    days: { type: Number, required: true },
    status: {
        type: String,
        enum: ['available', 'active', 'banned', 'disabled', 'paused', 'expired', 'blacklisted'],
        default: 'available'
    },
    hwid_locked: { type: Boolean, default: false },
    ban_message: { type: String, default: null },
    used_by: { type: String, default: null }, // Username
    created_at: { type: Date, default: Date.now },
    activated_at: { type: Date, default: null },
    expires_at: { type: Date, default: null },
    remaining_ms: { type: Number, default: null }, // For paused keys
    lifetime: { type: Boolean, default: false } // Never expires
});

const MenuKeySchema = new mongoose.Schema({
    id: { type: Number, required: true },
    key_code: { type: String, required: true, unique: true },
    days: { type: Number, required: true },
    status: {
        type: String,
        enum: ['available', 'active', 'expired', 'banned', 'disabled', 'paused'],
        default: 'available'
    },
    used_by: { type: String, default: null },
    activated_at: { type: Date, default: null },
    expires_at: { type: Date, default: null },
    lifetime: { type: Boolean, default: false } // Never expires
});

module.exports = {
    Key: mongoose.model('Key', KeySchema),
    MenuKey: mongoose.model('MenuKey', MenuKeySchema)
};
