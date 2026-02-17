require('dotenv').config();
const mongoose = require('mongoose');
const WhitelistIP = require('./models/WhitelistIP');

const MONGODB_URI = process.env.MONGODB_URI;

if (!MONGODB_URI) {
    console.error('Error: MONGODB_URI not found in environment');
    process.exit(1);
}

const action = process.argv[2];
const ip = process.argv[3];

if (!action || !['add', 'remove', 'list'].includes(action)) {
    console.log('Usage:');
    console.log('  node lk.js add <ip>');
    console.log('  node lk.js remove <ip>');
    console.log('  node lk.js list');
    process.exit(0);
}

async function run() {
    try {
        await mongoose.connect(MONGODB_URI);

        if (action === 'add') {
            if (!ip) return console.error('Error: IP required');
            await WhitelistIP.findOneAndUpdate({ ip }, { ip }, { upsert: true });
            console.log(`[SUCCESS] IP ${ip} added to whitelist.`);
        }
        else if (action === 'remove') {
            if (!ip) return console.error('Error: IP required');
            await WhitelistIP.deleteOne({ ip });
            console.log(`[SUCCESS] IP ${ip} removed from whitelist.`);
        }
        else if (action === 'list') {
            const list = await WhitelistIP.find();
            console.log('Whitelisted IPs:');
            list.forEach(item => console.log(` - ${item.ip} (Added: ${item.addedAt})`));
        }

        await mongoose.disconnect();
    } catch (err) {
        console.error('Error:', err);
    }
}

run();
