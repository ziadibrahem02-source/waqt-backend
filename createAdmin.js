require('dotenv').config();

const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const Admin = require('./models/Admin');

async function createAdmin() {
    const username = process.env.ADMIN_USERNAME;
    const password = process.env.ADMIN_PASSWORD;
    if (!username || username.trim().length < 3 || username.trim().length > 80) {
        throw new Error('Set ADMIN_USERNAME to a value between 3 and 80 characters.');
    }
    if (typeof password !== 'string' || password.length < 12 || password.length > 128) {
        throw new Error('Set ADMIN_PASSWORD to a password between 12 and 128 characters.');
    }

    await mongoose.connect(process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/waqt-store');
    const hashedPassword = await bcrypt.hash(password, 12);
    await Admin.findOneAndUpdate(
        { username: username.trim() },
        { $set: { username: username.trim(), password: hashedPassword } },
        { upsert: true, new: true, runValidators: true, setDefaultsOnInsert: true }
    );
    console.log('Admin credentials were securely stored.');
}

createAdmin()
    .catch((error) => {
        console.error('Could not configure admin account:', error.message);
        process.exitCode = 1;
    })
    .finally(async () => {
        if (mongoose.connection.readyState !== 0) await mongoose.disconnect();
    });
