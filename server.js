require('dotenv').config();

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { xss } = require('express-xss-sanitizer');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const User = require('./models/User');
const Watch = require('./models/Watch');
const Admin = require('./models/Admin');
const Order = require('./models/Order');
const adminAuth = require('./middleware/adminAuth');

const app = express();
const PORT = Number(process.env.PORT || 5000);
const JWT_SECRET = process.env.JWT_SECRET;
const JWT_ISSUER = 'waqt-api';
const ADMIN_AUDIENCE = 'waqt-admin';
const USER_AUDIENCE = 'waqt-user';
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
const EGYPT_PHONE_PATTERN = /^01[0125]\d{8}$/;
const PAYMENT_METHODS = new Set(['instapay', 'wallet', 'cod']);
const ALLOWED_GOVERNORATES = new Set([
    'القاهرة / Cairo', 'الإسكندرية / Alexandria', 'الجيزة / Giza', 'القليوبية / Qalyubia',
    'بورسعيد / Port Said', 'السويس / Suez', 'الإسماعيلية / Ismailia', 'الشرقية / Al Sharqia',
    'الدقهلية / Dakahlia', 'الغربية / Gharbia', 'المنوفية / Monufia', 'البحيرة / Beheira',
    'كفر الشيخ / Kafr El Sheikh', 'دمياط / Damietta', 'الفيوم / Faiyum', 'بني سويف / Beni Suef',
    'المنيا / Minya', 'أسيوط / Asyut', 'سوهاج / Sohag', 'قنا / Qena', 'الأقصر / Luxor',
    'أسوان / Aswan', 'البحر الأحمر / Red Sea', 'الوادي الجديد / New Valley', 'مطروح / Matrouh',
    'شمال سيناء / North Sinai', 'جنوب سيناء / South Sinai'
]);

if (typeof JWT_SECRET !== 'string' || Buffer.byteLength(JWT_SECRET, 'utf8') < 32) {
    throw new Error('JWT_SECRET must be set to a random secret of at least 32 bytes.');
}

const configuredOrigins = (process.env.CORS_ORIGINS || 'http://localhost:8080,http://127.0.0.1:8080,http://localhost:5500,http://127.0.0.1:5500,null')
    .split(',')
    .map((origin) => origin.trim())
    .filter(Boolean);

app.disable('x-powered-by');
app.use(helmet());
app.use(cors({
    origin(origin, callback) {
        if (!origin || configuredOrigins.includes(origin)) {
            callback(null, true);
            return;
        }
        callback(new Error('Origin is not allowed by CORS.'));
    },
    methods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json({ limit: '16mb', strict: true }));
app.use(express.urlencoded({ limit: '16mb', extended: false }));
app.use(xss());

const orderLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 5,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    message: { error: 'لقد تجاوزت الحد المسموح من الطلبات، يرجى المحاولة لاحقاً.' }
});

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 10,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    message: { error: 'محاولات كثيرة. يرجى المحاولة لاحقاً.' }
});

function isPlainObject(value) {
    return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function requiredText(value, minLength, maxLength) {
    return typeof value === 'string' && value.trim().length >= minLength && value.trim().length <= maxLength;
}

function passwordIsValid(value) {
    return typeof value === 'string' && value.length >= 8 && value.length <= 128;
}

function htmlEscape(value) {
    return String(value).replace(/[&<>"']/g, (character) => ({
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;'
    })[character]);
}

function publicError(res, status, message) {
    return res.status(status).json({ error: message });
}

app.get('/api/watches', async (req, res) => {
    try {
        const watches = await Watch.find().sort({ createdAt: -1 }).lean();
        res.json(watches);
    } catch (error) {
        console.error('Could not load public watches:', error.message);
        publicError(res, 500, 'تعذر تحميل الساعات.');
    }
});

app.post('/api/users/register', authLimiter, async (req, res) => {
    const { name, email, password } = req.body || {};
    const normalizedEmail = typeof email === 'string' ? email.trim().toLowerCase() : '';
    if (!requiredText(name, 2, 100) || !EMAIL_PATTERN.test(normalizedEmail) ||
        normalizedEmail.length > 254 || !passwordIsValid(password)) {
        return publicError(res, 400, 'بيانات التسجيل غير صحيحة.');
    }

    try {
        const existingUser = await User.findOne({ email: normalizedEmail }).select('_id');
        if (existingUser) return publicError(res, 409, 'هذا البريد مسجل مسبقاً.');
        const hashedPassword = await bcrypt.hash(password, 12);
        const newUser = await User.create({
            name: name.trim(),
            email: normalizedEmail,
            password: hashedPassword
        });
        res.status(201).json({ message: 'تم إنشاء الحساب بنجاح.', name: newUser.name });
    } catch (error) {
        if (error.code === 11000) return publicError(res, 409, 'هذا البريد مسجل مسبقاً.');
        console.error('Could not register user:', error.message);
        publicError(res, 500, 'تعذر إنشاء الحساب.');
    }
});

app.post('/api/users/login', authLimiter, async (req, res) => {
    const { email, password } = req.body || {};
    const normalizedEmail = typeof email === 'string' ? email.trim().toLowerCase() : '';
    if (!EMAIL_PATTERN.test(normalizedEmail) || normalizedEmail.length > 254 || !passwordIsValid(password)) {
        return publicError(res, 400, 'بيانات الدخول غير صحيحة.');
    }

    try {
        const user = await User.findOne({ email: normalizedEmail });
        if (!user || !await bcrypt.compare(password, user.password)) {
            return publicError(res, 401, 'بيانات الدخول غير صحيحة.');
        }
        const token = jwt.sign(
            { _id: user._id.toString(), role: 'user' },
            JWT_SECRET,
            { expiresIn: '30d', issuer: JWT_ISSUER, audience: USER_AUDIENCE, algorithm: 'HS256' }
        );
        res.json({ message: 'تم تسجيل الدخول.', token, name: user.name });
    } catch (error) {
        console.error('Could not sign in user:', error.message);
        publicError(res, 500, 'تعذر تسجيل الدخول.');
    }
});

app.post('/api/users/forgot-password', authLimiter, async (req, res) => {
    const email = typeof req.body?.email === 'string' ? req.body.email.trim().toLowerCase() : '';
    if (!EMAIL_PATTERN.test(email) || email.length > 254) {
        return publicError(res, 400, 'أدخل بريداً إلكترونياً صحيحاً.');
    }
    const smtpReady = process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS;
    if (!smtpReady) return publicError(res, 503, 'خدمة استعادة كلمة المرور غير مهيأة حالياً.');

    try {
        const user = await User.findOne({ email });
        if (!user) return res.json({ message: 'إذا كان البريد مسجلاً فسيتم إرسال رابط الاستعادة.' });
        const resetToken = jwt.sign(
            { id: user._id.toString(), purpose: 'password-reset' },
            JWT_SECRET,
            { expiresIn: '15m', issuer: JWT_ISSUER, audience: USER_AUDIENCE, algorithm: 'HS256' }
        );
        const frontendUrl = String(process.env.FRONTEND_URL || 'http://localhost:8080').replace(/\/+$/, '');
        const resetLink = `${frontendUrl}/index.html?reset_token=${encodeURIComponent(resetToken)}`;
        const transporter = nodemailer.createTransport({
            host: process.env.SMTP_HOST,
            port: Number(process.env.SMTP_PORT || 587),
            secure: process.env.SMTP_SECURE === 'true',
            auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
        });
        await transporter.sendMail({
            from: process.env.SMTP_FROM || process.env.SMTP_USER,
            to: email,
            subject: 'استعادة كلمة المرور - WAQT Timepieces',
            html: `<div style="text-align:right;direction:rtl;font-family:Arial;padding:20px"><h2>مرحباً ${htmlEscape(user.name)}،</h2><p>طلبت إعادة تعيين كلمة المرور. الرابط صالح لمدة 15 دقيقة.</p><a href="${htmlEscape(resetLink)}">تغيير كلمة المرور</a></div>`
        });
        res.json({ message: 'تم إرسال رابط الاستعادة إذا كان البريد مسجلاً.' });
    } catch (error) {
        console.error('Could not send password reset email:', error.message);
        publicError(res, 503, 'تعذر إرسال رسالة استعادة كلمة المرور.');
    }
});

app.post('/api/users/reset-password', authLimiter, async (req, res) => {
    const { token, newPassword } = req.body || {};
    if (typeof token !== 'string' || token.length > 4096 || !passwordIsValid(newPassword)) {
        return publicError(res, 400, 'بيانات إعادة تعيين كلمة المرور غير صحيحة.');
    }
    try {
        const decoded = jwt.verify(token, JWT_SECRET, {
            algorithms: ['HS256'],
            issuer: JWT_ISSUER,
            audience: USER_AUDIENCE
        });
        if (decoded.purpose !== 'password-reset' || typeof decoded.id !== 'string') {
            return publicError(res, 400, 'الرابط غير صالح أو انتهت صلاحيته.');
        }
        const user = await User.findById(decoded.id);
        if (!user) return publicError(res, 400, 'الرابط غير صالح أو انتهت صلاحيته.');
        user.password = await bcrypt.hash(newPassword, 12);
        await user.save();
        res.json({ message: 'تم تغيير كلمة المرور بنجاح.' });
    } catch (error) {
        if (error.name !== 'JsonWebTokenError' && error.name !== 'TokenExpiredError') {
            console.error('Could not reset user password:', error.message);
        }
        publicError(res, 400, 'الرابط غير صالح أو انتهت صلاحيته.');
    }
});

app.post('/api/admin/login', authLimiter, async (req, res) => {
    const { username, password } = req.body || {};
    if (!requiredText(username, 1, 80) || !passwordIsValid(password)) {
        return publicError(res, 401, 'بيانات الدخول غير صحيحة.');
    }
    try {
        const admin = await Admin.findOne({ username: username.trim() });
        if (!admin || !await bcrypt.compare(password, admin.password)) {
            return publicError(res, 401, 'بيانات الدخول غير صحيحة.');
        }
        const token = jwt.sign(
            { _id: admin._id.toString(), role: 'admin' },
            JWT_SECRET,
            { expiresIn: '8h', issuer: JWT_ISSUER, audience: ADMIN_AUDIENCE, algorithm: 'HS256' }
        );
        res.json({ message: 'تم تسجيل الدخول.', token });
    } catch (error) {
        console.error('Could not sign in admin:', error.message);
        publicError(res, 500, 'تعذر تسجيل الدخول.');
    }
});

app.post('/api/orders', orderLimiter, async (req, res) => {
    const body = req.body;
    if (!isPlainObject(body) || !isPlainObject(body.customerDetails) ||
        !Array.isArray(body.items) || body.items.length < 1 || body.items.length > 25) {
        return publicError(res, 400, 'بيانات الطلب غير صحيحة.');
    }

    const customer = body.customerDetails;
    const fullName = typeof customer.fullName === 'string' ? customer.fullName.trim() : '';
    const email = typeof customer.email === 'string' ? customer.email.trim().toLowerCase() : '';
    const phone1 = typeof customer.phone === 'string' ? customer.phone.trim() : '';
    const phone2 = typeof customer.phone2 === 'string' ? customer.phone2.trim() : '';
    const governorate = typeof customer.governorate === 'string' ? customer.governorate.trim() : '';
    const address = typeof customer.address === 'string' ? customer.address.trim() : '';
    const notes = typeof customer.notes === 'string' ? customer.notes.trim() : '';
    const paymentMethod = customer.paymentMethod;

    if (!requiredText(fullName, 2, 100) || !EMAIL_PATTERN.test(email) || email.length > 254 ||
        !EGYPT_PHONE_PATTERN.test(phone1) || (phone2 && !EGYPT_PHONE_PATTERN.test(phone2)) ||
        !ALLOWED_GOVERNORATES.has(governorate) || !requiredText(address, 8, 500) ||
        notes.length > 500 || !PAYMENT_METHODS.has(paymentMethod)) {
        return publicError(res, 400, 'يرجى التحقق من بيانات العميل والعنوان والهاتف وطريقة الدفع.');
    }

    const quantities = new Map();
    for (const item of body.items) {
        if (!isPlainObject(item) || typeof item.watchId !== 'string' ||
            !mongoose.isValidObjectId(item.watchId) || !Number.isInteger(item.quantity) ||
            item.quantity < 1 || item.quantity > 99) {
            return publicError(res, 400, 'تحتوي السلة على منتج أو كمية غير صالحة.');
        }
        const id = new mongoose.Types.ObjectId(item.watchId).toString();
        const quantity = (quantities.get(id) || 0) + item.quantity;
        if (quantity > 99) return publicError(res, 400, 'الحد الأقصى لكمية المنتج هو 99.');
        quantities.set(id, quantity);
    }

    try {
        const watches = await Watch.find({ _id: { $in: [...quantities.keys()] } }).select('_id price').lean();
        const watchesById = new Map(watches.map((watch) => [watch._id.toString(), watch]));
        if (watchesById.size !== quantities.size) {
            return publicError(res, 400, 'أحد المنتجات لم يعد متاحاً.');
        }
        const items = [...quantities.entries()].map(([watchId, quantity]) => {
            const watch = watchesById.get(watchId);
            return { watchId, quantity, price: watch.price };
        });
        const totalAmount = items.reduce((sum, item) => sum + item.price * item.quantity, 0);
        if (!Number.isFinite(totalAmount) || totalAmount <= 0 || totalAmount > 1_000_000_000) {
            return publicError(res, 400, 'تعذر حساب إجمالي الطلب.');
        }

        const order = await Order.create({
            items,
            totalAmount,
            customerDetails: {
                name: fullName,
                email,
                phone1,
                phone2,
                governorate,
                address,
                paymentMethod,
                notes
            }
        });
        res.status(201).json({ message: 'تم استلام الطلب.', orderId: order._id, totalAmount });
    } catch (error) {
        console.error('Could not create order:', error.message);
        publicError(res, 500, 'تعذر حفظ الطلب.');
    }
});

app.get('/api/admin/orders', adminAuth, async (req, res) => {
    try {
        const orders = await Order.find()
            .sort({ createdAt: -1 })
            .populate('watchId', 'nameAr nameEn price')
            .populate('items.watchId', 'nameAr nameEn price')
            .lean();
        res.json(orders);
    } catch (error) {
        console.error('Could not load admin orders:', error.message);
        publicError(res, 500, 'تعذر تحميل الطلبات.');
    }
});

app.post('/api/admin/watches', adminAuth, async (req, res) => {
    const body = req.body;
    if (!isPlainObject(body) || !requiredText(body.nameAr, 2, 120) ||
        !requiredText(body.nameEn, 2, 120) || !Number.isFinite(body.price) ||
        body.price <= 0 || body.price > 100_000_000 || !Array.isArray(body.images) ||
        body.images.length < 1 || body.images.length > 8 ||
        body.images.some((image) => typeof image !== 'string' || image.length > 2_000_000 ||
            !/^data:image\/jpeg;base64,[a-z0-9+/]+=*$/i.test(image))) {
        return publicError(res, 400, 'بيانات المنتج أو صوره غير صالحة.');
    }

    try {
        const watch = await Watch.create({
            nameAr: body.nameAr.trim(),
            nameEn: body.nameEn.trim(),
            price: body.price,
            descAr: typeof body.descAr === 'string' ? body.descAr.trim().slice(0, 1500) : '',
            descEn: typeof body.descEn === 'string' ? body.descEn.trim().slice(0, 1500) : '',
            images: body.images
        });
        res.status(201).json({ message: 'تمت إضافة الساعة بنجاح.', watch });
    } catch (error) {
        console.error('Could not add watch:', error.message);
        publicError(res, 500, 'تعذر إضافة الساعة.');
    }
});

app.delete('/api/admin/watches/:id', adminAuth, async (req, res) => {
    if (!mongoose.isValidObjectId(req.params.id)) return publicError(res, 400, 'معرّف المنتج غير صالح.');
    try {
        const deleted = await Watch.findByIdAndDelete(req.params.id);
        if (!deleted) return publicError(res, 404, 'المنتج غير موجود.');
        res.json({ message: 'تم حذف الساعة بنجاح.' });
    } catch (error) {
        console.error('Could not delete watch:', error.message);
        publicError(res, 500, 'تعذر حذف الساعة.');
    }
});

app.get('/api/admin/watches', adminAuth, async (req, res) => {
    try {
        const watches = await Watch.find().sort({ createdAt: -1 }).lean();
        res.json(watches);
    } catch (error) {
        console.error('Could not load admin watches:', error.message);
        publicError(res, 500, 'تعذر تحميل الساعات.');
    }
});

app.use((error, req, res, next) => {
    if (res.headersSent) return next(error);
    if (error.type === 'entity.too.large') return publicError(res, 413, 'حجم البيانات أكبر من المسموح.');
    if (error instanceof SyntaxError && Object.prototype.hasOwnProperty.call(error, 'body')) {
        return publicError(res, 400, 'صيغة JSON غير صحيحة.');
    }
    if (error.message === 'Origin is not allowed by CORS.') {
        return publicError(res, 403, 'مصدر الطلب غير مسموح.');
    }
    console.error('Unhandled API error:', error.message);
    publicError(res, 500, 'حدث خطأ غير متوقع.');
});

async function startServer() {
    await mongoose.connect(process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/waqt-store');
    app.listen(PORT, () => {
        console.log(`WAQT API is running on port ${PORT}`);
    });
}

startServer().catch((error) => {
    console.error('Could not start WAQT API:', error.message);
    process.exitCode = 1;
});
