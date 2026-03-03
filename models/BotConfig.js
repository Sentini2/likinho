const mongoose = require('mongoose');

const botConfigSchema = new mongoose.Schema({
    id: { type: Number, required: true, unique: true }, // Permite multi-bots no futuro
    bot_token: { type: String, default: '' },
    prefix: { type: String, default: '!' },
    sales_channel_id: { type: String, default: '' },
    log_channel_id: { type: String, default: '' },
    dm_message_template: {
        type: String,
        default: 'Obrigado pela compra!\nAqui está o seu produto:\n{produto}'
    },
    embed_color: { type: String, default: '#00ff33' }
});

module.exports = mongoose.model('BotConfig', botConfigSchema);
