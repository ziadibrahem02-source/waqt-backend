const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const Admin = require('../models/Admin');

const JWT_ISSUER = 'waqt-api';
const ADMIN_AUDIENCE = 'waqt-admin';

module.exports = async function adminAuth(req, res, next) {
    const authorization = req.get('Authorization') || '';
    const match = /^Bearer ([^\s]{1,4096})$/.exec(authorization);
    if (!match) {
        return res.status(401).json({ error: 'غير مصرح لك بالدخول.' });
    }

    const secret = process.env.JWT_SECRET;
    if (typeof secret !== 'string' || Buffer.byteLength(secret, 'utf8') < 32) {
        return res.status(503).json({ error: 'إعدادات الجلسة غير متاحة.' });
    }

    try {
        const verified = jwt.verify(match[1], secret, {
            algorithms: ['HS256'],
            issuer: JWT_ISSUER,
            audience: ADMIN_AUDIENCE
        });
        if (verified.role !== 'admin' || typeof verified._id !== 'string' ||
            !mongoose.isValidObjectId(verified._id)) {
            return res.status(403).json({ error: 'ليس لديك صلاحية إدارة.' });
        }
        const admin = await Admin.findById(verified._id).select('_id').lean();
        if (!admin) return res.status(401).json({ error: 'جلسة الإدارة غير صالحة.' });
        req.admin = { _id: admin._id.toString(), role: 'admin' };
        next();
    } catch (error) {
        if (error.name !== 'JsonWebTokenError' && error.name !== 'TokenExpiredError') {
            console.error('Admin authorization failed:', error.message);
            return res.status(500).json({ error: 'تعذر التحقق من الجلسة.' });
        }
        res.status(401).json({ error: 'تصريح غير صالح أو منتهي الصلاحية.' });
    }
};
