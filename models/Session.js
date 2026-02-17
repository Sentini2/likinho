const mongoose = require('mongoose');

const SessionSchema = new mongoose.Schema({
    id: { type: Number, required: true },
    token: { type: String, required: true, unique: true },
    username: { type: String, required: true },
    ip: { type: String, required: true },
    last_heartbeat: { type: Date, default: Date.now },
    created_at: { type: Date, default: Date.now }
});

// Auto-expire sessions after 24 hours of no heartbeat
SessionSchema.index({ last_heartbeat: 1 }, { expireAfterSeconds: 86400 });

module.exports = mongoose.model('Session', SessionSchema);
