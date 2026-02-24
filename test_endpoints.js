const axios = require('axios');

const ADMIN_TOKEN = 'likinho-admin-2024';
const BASE_URL = 'http://localhost:3000';

async function testEndpoints() {
    try {
        console.log('\n╔════════════════════════════════════════════╗');
        console.log('║   LiKinho KeyAuth - Endpoint Test         ║');
        console.log('╚════════════════════════════════════════════╝\n');

        // Test Stats
        console.log('📊 Testing /api/admin/stats...');
        const stats = await axios.get(`${BASE_URL}/api/admin/stats`, {
            headers: { 'x-admin-token': ADMIN_TOKEN }
        });
        console.log('✅ Stats:', stats.data);
        console.log('');

        // Test Generate Keys
        console.log('🔑 Testing /api/admin/keys/generate (creating 2 keys)...');
        const generate = await axios.post(`${BASE_URL}/api/admin/keys/generate`,
            { days: 30, count: 2 },
            { headers: { 'x-admin-token': ADMIN_TOKEN, 'Content-Type': 'application/json' } }
        );
        console.log('✅ Generated:', generate.data);
        console.log('');

        // Test List Keys
        console.log('📋 Testing /api/admin/keys (listing all keys)...');
        const keys = await axios.get(`${BASE_URL}/api/admin/keys`, {
            headers: { 'x-admin-token': ADMIN_TOKEN }
        });
        console.log(`✅ Found ${keys.data.keys.length} keys`);
        console.log('');

        // Test List Users
        console.log('👥 Testing /api/admin/users...');
        const users = await axios.get(`${BASE_URL}/api/admin/users`, {
            headers: { 'x-admin-token': ADMIN_TOKEN }
        });
        console.log(`✅ Found ${users.data.users.length} users`);
        console.log('');

        // Test Online Users
        console.log('🌐 Testing /api/admin/online...');
        const online = await axios.get(`${BASE_URL}/api/admin/online`, {
            headers: { 'x-admin-token': ADMIN_TOKEN }
        });
        console.log(`✅ Online users: ${online.data.count}`);
        console.log('');

        console.log('╔════════════════════════════════════════════╗');
        console.log('║   ✅ ALL ENDPOINTS WORKING!                ║');
        console.log('╚════════════════════════════════════════════╝\n');

        console.log('🌐 Web Panel: http://localhost:3000');
        console.log('🔐 Admin Token: likinho-admin-2024\n');

    } catch (error) {
        console.error('❌ Error:', error.message);
        if (error.response) {
            console.error('Response:', error.response.data);
        }
    }
}

testEndpoints();
