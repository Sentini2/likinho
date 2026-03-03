const mongoose = require('mongoose');

const TicketMessageSchema = new mongoose.Schema({
    from: { type: String, required: true },
    text: { type: String, required: true },
    role: { type: String, required: true }, // 'user' or 'admin'
    time: { type: Date, default: Date.now }
});

const TicketSchema = new mongoose.Schema({
    id: { type: Number, required: true },
    username: { type: String, required: true },
    subject: { type: String, required: true },
    status: { type: String, default: 'open' }, // 'open', 'closed'
    messages: [TicketMessageSchema],
    created_at: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Ticket', TicketSchema);
