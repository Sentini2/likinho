const mongoose = require('mongoose');

const productSchema = new mongoose.Schema({
    id: { type: Number, required: true, unique: true },
    name: { type: String, required: true },
    description: { type: String, default: '' },
    price: { type: Number, required: true },
    stock_items: { type: [String], default: [] },
    created_at: { type: String, required: true }
});

module.exports = mongoose.model('Product', productSchema);
