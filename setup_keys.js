const fs = require('fs');
const path = require('path');

// Load database
const DB_PATH = path.join(__dirname, 'data.json');
let db = JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));

// Generate new key
function generateKey() {
    const c = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let p1 = '', p2 = '';
    for (let i = 0; i < 8; i++) p1 += c[Math.floor(Math.random() * c.length)];
    for (let i = 0; i < 12; i++) p2 += c[Math.floor(Math.random() * c.length)];
    return `LIKINHO-${p1}-${p2}`;
}

// Create multiple keys for testing
const testKeys = [
    { days: 7, status: 'disabled' },
    { days: 30, status: 'disabled' },
    { days: 90, status: 'disabled' },
    { days: 1, status: 'disabled' }
];

testKeys.forEach((keyInfo, index) => {
    const newKey = {
        id: db.keys.length > 0 ? Math.max(...db.keys.map(k => k.id)) + 1 : 1,
        key_code: generateKey(),
        days: keyInfo.days,
        status: keyInfo.status,
        ban_message: null,
        used_by: null,
        created_at: new Date().toISOString(),
        activated_at: null,
        expires_at: null
    };
    
    db.keys.push(newKey);
    console.log(`✅ Key ${index + 1}: ${newKey.key_code} (${keyInfo.days} dias)`);
});

fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2));

console.log('\n🎉 Keys criadas com sucesso!');
console.log('📝 Total de keys:', db.keys.length);
console.log('\n🔑 Keys disponíveis:');
db.keys.filter(k => k.status === 'disabled').forEach((key, index) => {
    console.log(`${index + 1}. ${key.key_code} - ${key.days} dias`);
});
