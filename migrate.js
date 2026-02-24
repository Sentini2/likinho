require('dotenv').config();
const dns = require('dns');
try { dns.setServers(['8.8.8.8', '8.8.4.4']); } catch (e) { console.error('DNS fix failed'); }

const mongoose = require('mongoose');
const fs = require('fs');
const path = require('path');
const User = require('./models/User');
const { Key, MenuKey } = require('./models/Key');
const Session = require('./models/Session');
const Activity = require('./models/Activity');
const Message = require('./models/Message');
const Ticket = require('./models/Ticket');

// Configuration
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/likinho_db';
const DATA_FILE = path.join(__dirname, 'data.json');
const CHAT_FILE = path.join(__dirname, 'chat.json');

async function migrate() {
    console.log('Starting migration...');

    if (!fs.existsSync(DATA_FILE)) {
        console.error('Data file not found!');
        process.exit(1);
    }

    try {
        const data = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));

        await mongoose.connect(MONGODB_URI);
        console.log('Connected to MongoDB');

        // users
        if (data.users && data.users.length > 0) {
            console.log(`Migrating ${data.users.length} users...`);
            for (const u of data.users) {
                const existing = await User.findOne({ username: u.username });
                if (!existing) {
                    await User.create(u);
                }
            }
        }

        // keys
        if (data.keys && data.keys.length > 0) {
            console.log(`Migrating ${data.keys.length} keys...`);
            for (const k of data.keys) {
                const existing = await Key.findOne({ key_code: k.key_code });
                if (!existing) {
                    await Key.create(k);
                }
            }
        }

        // menu keys
        if (data.menu_keys && data.menu_keys.length > 0) {
            console.log(`Migrating ${data.menu_keys.length} menu keys...`);
            for (const k of data.menu_keys) {
                const existing = await MenuKey.findOne({ key_code: k.key_code });
                if (!existing) {
                    await MenuKey.create(k);
                }
            }
        }

        // storage activities
        if (data.suspicious_activities && data.suspicious_activities.length > 0) {
            console.log(`Migrating ${data.suspicious_activities.length} activities...`);
            for (const a of data.suspicious_activities) {
                // simple check using id if available, otherwise just insert
                const existing = await Activity.findOne({ id: a.id });
                if (!existing) {
                    await Activity.create(a);
                }
            }
        }

        // tickets
        if (data.tickets && data.tickets.length > 0) {
            console.log(`Migrating ${data.tickets.length} tickets...`);
            for (const t of data.tickets) {
                const existing = await Ticket.findOne({ id: t.id });
                if (!existing) {
                    await Ticket.create(t);
                }
            }
        }

        // sessions are transient, maybe skip? But let's migrate anyway if active
        if (data.sessions && data.sessions.length > 0) {
            console.log(`Migrating ${data.sessions.length} sessions...`);
            await Session.deleteMany({}); // clear old sessions to avoid conflicts or duplicates
            await Session.insertMany(data.sessions);
        }

        // Chat migration
        if (fs.existsSync(CHAT_FILE)) {
            try {
                const chatData = JSON.parse(fs.readFileSync(CHAT_FILE, 'utf8'));
                if (chatData.messages && chatData.messages.length > 0) {
                    console.log(`Migrating ${chatData.messages.length} chat messages...`);
                    // Check if already migrated to avoid duplicates? 
                    // Since messages don't have IDs, this is tricky. We'll just check if collection is empty.
                    const msgCount = await Message.countDocuments();
                    if (msgCount === 0) {
                        for (const m of chatData.messages) {
                            await Message.create({
                                username: m.username,
                                text: m.text,
                                role: m.role || 'user',
                                avatar: m.avatar,
                                timestamp: m.timestamp || Date.now(),
                                created_at: m.time ? new Date() : Date.now() // approximate
                            });
                        }
                    }
                }
            } catch (e) {
                console.error('Failed to migrate chat:', e);
            }
        }

        console.log('Migration completed successfully!');
        process.exit(0);

    } catch (error) {
        console.error('Migration failed:', error);
        process.exit(1);
    }
}

migrate();
