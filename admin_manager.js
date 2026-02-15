const axios = require('axios');

const ADMIN_TOKEN = 'likinho-admin-2024';
const BASE_URL = 'http://localhost:3000';

// Helper function to make admin requests
async function adminRequest(method, endpoint, data = null) {
    try {
        const config = {
            method,
            url: `${BASE_URL}${endpoint}`,
            headers: {
                'X-Admin-Token': ADMIN_TOKEN,
                'Content-Type': 'application/json'
            }
        };

        if (data) {
            config.data = data;
        }

        const response = await axios(config);
        return response.data;
    } catch (error) {
        console.error('Error:', error.message);
        return null;
    }
}

// Create a new key
async function createKey(days = 30) {
    console.log(`\n🔑 Creating new key with ${days} days...`);
    const result = await adminRequest('POST', '/api/admin/key/create', { days });

    if (result && result.success) {
        console.log('✅ Key created successfully!');
        console.log('📋 Key Code:', result.key.key_code);
        console.log('⏰ Days:', result.key.days);
        console.log('📊 Status:', result.key.status);
        console.log('🆔 ID:', result.key.id);
        return result.key;
    } else {
        console.log('❌ Failed to create key');
        return null;
    }
}

// List all keys
async function listKeys() {
    console.log('\n📋 Listing all keys...');
    const result = await adminRequest('GET', '/api/admin/keys/list');

    if (result && result.success) {
        console.log(`\n✅ Found ${result.keys.length} keys:\n`);
        result.keys.forEach(key => {
            console.log(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);
            console.log(`🆔 ID: ${key.id}`);
            console.log(`🔑 Key Code: ${key.key_code}`);
            console.log(`⏰ Days: ${key.days}`);
            console.log(`📊 Status: ${key.status}`);
            console.log(`👤 Used by: ${key.used_by || 'N/A'}`);
            console.log(`📅 Created: ${new Date(key.created_at).toLocaleString()}`);
            if (key.expires_at) {
                console.log(`⌛ Expires: ${new Date(key.expires_at).toLocaleString()}`);
            }
        });
        console.log(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n`);
        return result.keys;
    } else {
        console.log('❌ Failed to list keys');
        return null;
    }
}

// Main menu
async function main() {
    const args = process.argv.slice(2);

    if (args.length === 0) {
        console.log('\n╔════════════════════════════════════════╗');
        console.log('║   LiKinho KeyAuth - Admin Manager     ║');
        console.log('╚════════════════════════════════════════╝\n');
        console.log('Usage:');
        console.log('  node admin_manager.js create [days]  - Create a new key (default: 30 days)');
        console.log('  node admin_manager.js list           - List all keys');
        console.log('\nExamples:');
        console.log('  node admin_manager.js create         - Create a 30-day key');
        console.log('  node admin_manager.js create 7       - Create a 7-day key');
        console.log('  node admin_manager.js list           - Show all keys\n');
        return;
    }

    const command = args[0].toLowerCase();

    switch (command) {
        case 'create':
            const days = args[1] ? parseInt(args[1]) : 30;
            await createKey(days);
            break;

        case 'list':
            await listKeys();
            break;

        default:
            console.log('❌ Unknown command:', command);
            console.log('Use: create, list');
    }
}

main();
