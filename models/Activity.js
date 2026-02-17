const mongoose = require('mongoose');

const ActivitySchema = new mongoose.Schema({
    id: { type: Number, required: true },
    user_id: { type: Number, default: null },
    username: { type: String, required: true },
    process_name: { type: String, required: true },
    threat_type: { type: String, required: true },
    screenshot_url: { type: String, default: null },
    hwid: { type: String, default: null },
    old_hwid: { type: String, default: null },
    ip: { type: String, default: null },
    detected_at: { type: Date, default: Date.now },
    auto_action: { type: String, default: 'logged' }
});

module.exports = mongoose.model('Activity', ActivitySchema);
