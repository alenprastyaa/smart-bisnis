// server.js
require('dotenv').config();
const express = require('express');
const { Sequelize, DataTypes, Op } = require('sequelize');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const path = require('path');
const multer = require('multer');
const { S3Client, PutObjectCommand } = require('@aws-sdk/client-s3');

const app = express();
const JWT_SECRET = process.env.JWT_SECRET || 'change-this-secret-in-production';
const R2_ENDPOINT = process.env.R2_ENDPOINT || '';
const R2_BUCKET = process.env.R2_BUCKET || '';
const R2_ACCESS_KEY_ID = process.env.R2_ACCESS_KEY_ID || '';
const R2_SECRET_ACCESS_KEY = process.env.R2_SECRET_ACCESS_KEY || '';
const R2_PUBLIC_BASE_URL = (process.env.R2_PUBLIC_BASE_URL || '').replace(/\/$/, '');

const defaultLanding = {
    brandName: 'Ruang Tumbuh AI',
    badge: 'Kelas praktis untuk pebisnis & kreator',
    heroTitle: 'Bangun produk digital dengan AI, tanpa menunggu jadi ahli.',
    heroDescription: 'Belajar dari ide sampai aplikasi siap pakai melalui video terarah, studi kasus nyata, dan sesi mentoring bersama praktisi.',
    primaryCta: 'Mulai belajar sekarang',
    secondaryCta: 'Lihat kurikulum',
    studentsCount: '1.200+',
    rating: '4.9/5',
    projectsCount: '18+',
    sectionTitle: 'Bukan sekadar menonton tutorial',
    sectionDescription: 'Kurikulum ringkas yang membantu Anda mengeksekusi ide menjadi produk yang benar-benar bisa digunakan.',
    featureOneTitle: 'Belajar terarah',
    featureOneText: 'Materi berurutan dari fondasi prompt, otomasi, hingga deployment aplikasi.',
    featureTwoTitle: 'Proyek nyata',
    featureTwoText: 'Bangun portofolio dari studi kasus bisnis yang relevan dan dapat dikembangkan.',
    featureThreeTitle: 'Akses komunitas',
    featureThreeText: 'Diskusi, review proyek, dan dukungan saat Anda menemukan hambatan.',
    mentorName: 'Ardi Pratama',
    mentorRole: 'AI Product Builder & Mentor',
    mentorBio: 'Mendampingi pemilik bisnis dan kreator membangun sistem digital yang sederhana, relevan, dan menghasilkan.',
    testimonialQuote: 'Materinya langsung bisa dipraktikkan. Dalam dua minggu saya berhasil membuat dashboard operasional sendiri.',
    testimonialName: 'Dina, Owner Dapur Rasa',
    footerText: 'Belajar AI dengan cara yang lebih masuk akal.'
};

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// --- DATABASE CONNECTION ---
const sequelize = new Sequelize(
    process.env.DB_NAME || 'smartbisnis',
    process.env.DB_USER || 'root',
    process.env.DB_PASSWORD || '',
    {
    host: process.env.DB_HOST || 'localhost',
    port: Number(process.env.DB_PORT) || 3306,
    dialect: 'mysql',
    logging: false
    }
);

// --- MODELS ---
const User = sequelize.define('User', {
    username: { type: DataTypes.STRING, unique: true, allowNull: false },
    password: { type: DataTypes.STRING, allowNull: false }
});

const Setting = sequelize.define('Setting', {
    key: { type: DataTypes.STRING, unique: true, allowNull: false },
    value: { type: DataTypes.TEXT, allowNull: false }
});

const Course = sequelize.define('Course', {
    title: { type: DataTypes.STRING, allowNull: false },
    description: { type: DataTypes.TEXT, allowNull: false, defaultValue: '' },
    price: { type: DataTypes.INTEGER, allowNull: false },
    originalPrice: { type: DataTypes.INTEGER, allowNull: false, defaultValue: 0 },
    benefits: { type: DataTypes.TEXT, allowNull: false },
    stock: { type: DataTypes.INTEGER, allowNull: false, defaultValue: 0 },
    isActive: { type: DataTypes.BOOLEAN, allowNull: false, defaultValue: true }
});

const Transaction = sequelize.define('Transaction', {
    buyerName: { type: DataTypes.STRING, allowNull: false },
    buyerEmail: { type: DataTypes.STRING, allowNull: false },
    buyerWhatsapp: { type: DataTypes.STRING, allowNull: false },
    productId: { type: DataTypes.INTEGER, allowNull: true },
    productTitle: { type: DataTypes.STRING, allowNull: false, defaultValue: '' },
    paymentMethod: { type: DataTypes.STRING, allowNull: false, defaultValue: '' },
    paymentAccount: { type: DataTypes.STRING, allowNull: false, defaultValue: '' },
    paymentProofUrl: { type: DataTypes.TEXT, allowNull: false, defaultValue: '' },
    status: { type: DataTypes.ENUM('PENDING', 'APPROVED', 'REJECTED'), defaultValue: 'PENDING' },
    amount: { type: DataTypes.INTEGER, allowNull: false }
});

// --- MIDDLEWARE AUTH ---
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Unauthorized' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: 'Forbidden' });
        req.user = user;
        next();
    });
};

const getJsonSetting = async (key, fallback) => {
    const setting = await Setting.findOne({ where: { key } });
    if (!setting) return fallback;
    try {
        const parsed = JSON.parse(setting.value);
        if (Array.isArray(fallback)) return Array.isArray(parsed) ? parsed : fallback;
        return { ...fallback, ...parsed };
    }
    catch (_) { return fallback; }
};

const cleanText = (value, max = 500) => String(value || '').trim().slice(0, max);
const sanitizeBenefits = value => cleanText(value, 3000);
const sanitizeProduct = product => sanitizeProducts([product])[0] || null;
const sanitizeProducts = (products = []) => (
    Array.isArray(products) ? products : []
).map(product => ({
    id: Number.parseInt(product.id, 10) || null,
    title: cleanText(product.title, 150),
    description: cleanText(product.description, 700),
    price: Math.max(0, Number.parseInt(product.price, 10) || 0),
    originalPrice: Math.max(0, Number.parseInt(product.originalPrice, 10) || 0),
    stock: Math.max(0, Number.parseInt(product.stock, 10) || 0),
    benefits: sanitizeBenefits(product.benefits),
    isActive: Boolean(product.isActive)
})).filter(product => product.title);
const sanitizePaymentMethods = (items = []) => (
    Array.isArray(items) ? items : []
).map(item => ({
    id: cleanText(item.id, 80) || `payment-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    name: cleanText(item.name, 60),
    number: cleanText(item.number, 80),
    owner: cleanText(item.owner, 100),
    note: cleanText(item.note, 180),
    isActive: Boolean(item.isActive)
})).filter(item => item.name && item.number && item.owner);
const defaultPaymentMethods = [
    { id: 'bank-bca', name: 'BCA', number: '1234567890', owner: 'Ruang Tumbuh AI', note: 'Transfer bank', isActive: true }
];
const upload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: 5 * 1024 * 1024 },
    fileFilter: (_req, file, cb) => {
        if (!file.mimetype.startsWith('image/')) return cb(new Error('Bukti pembayaran harus berupa gambar'));
        cb(null, true);
    }
});
const hasR2Config = Boolean(R2_ENDPOINT && R2_BUCKET && R2_ACCESS_KEY_ID && R2_SECRET_ACCESS_KEY && R2_PUBLIC_BASE_URL);
const s3 = hasR2Config ? new S3Client({
    region: 'auto',
    endpoint: R2_ENDPOINT,
    credentials: {
        accessKeyId: R2_ACCESS_KEY_ID,
        secretAccessKey: R2_SECRET_ACCESS_KEY
    }
}) : null;
const buildPublicFileUrl = key => `${R2_PUBLIC_BASE_URL}/${key}`;
const fileExtensionFromName = name => {
    const ext = path.extname(String(name || '')).toLowerCase();
    return ext && ext.length <= 10 ? ext : '.jpg';
};
const uploadProofToR2 = async file => {
    if (!hasR2Config || !s3) throw new Error('Konfigurasi R2 belum lengkap');
    const key = `payment-proofs/${Date.now()}-${Math.random().toString(36).slice(2, 10)}${fileExtensionFromName(file.originalname)}`;
    await s3.send(new PutObjectCommand({
        Bucket: R2_BUCKET,
        Key: key,
        Body: file.buffer,
        ContentType: file.mimetype
    }));
    return buildPublicFileUrl(key);
};

// --- API ROUTES ---

// Auth Login
app.post('/api/auth/login', async (req, res) => {
    const username = cleanText(req.body.username, 100);
    const password = String(req.body.password || '');
    if (!username || !password) return res.status(400).json({ message: 'Username dan password wajib diisi' });
    try {
        const user = await User.findOne({ where: { username } });
        if (!user) return res.status(404).json({ message: 'User tidak ditemukan' });

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.status(400).json({ message: 'Password salah' });

        const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '1d' });
        res.json({ token, username: user.username });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Public: Ambil Data Landing Page (Dinamis)
app.get('/api/public/landing', async (req, res) => {
    try {
        const paymentMethods = await getJsonSetting('payment_methods', defaultPaymentMethods);
        const content = await getJsonSetting('landing_content', defaultLanding);
        const products = await Course.findAll({ where: { isActive: true }, order: [['id', 'DESC']] });
        const firstAvailableProduct = products.find(item => item.stock > 0) || products[0] || null;
        res.json({
            paymentMethods: paymentMethods.filter(item => item.isActive !== false),
            content,
            products,
            course: firstAvailableProduct || { title: 'AI Product Builder', description: '', price: 0, originalPrice: 0, stock: 0, benefits: 'Video pembelajaran,Template siap pakai,Akses komunitas,Sertifikat kelulusan' }
        });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Public: Kirim Transaksi / Checkout
app.post('/api/public/checkout', upload.single('paymentProof'), async (req, res) => {
    const buyerName = cleanText(req.body.buyerName, 120);
    const buyerEmail = cleanText(req.body.buyerEmail, 160).toLowerCase();
    const buyerWhatsapp = cleanText(req.body.buyerWhatsapp, 30);
    const productId = Number.parseInt(req.body.productId, 10);
    const paymentMethodId = cleanText(req.body.paymentMethodId, 80);
    try {
        if (!hasR2Config) return res.status(500).json({ message: 'Upload bukti pembayaran belum dikonfigurasi' });
        if (!buyerName || !/^\S+@\S+\.\S+$/.test(buyerEmail) || !/^[+\d][\d\s-]{7,}$/.test(buyerWhatsapp)) {
            return res.status(400).json({ message: 'Data pembeli belum lengkap atau formatnya tidak valid' });
        }
        if (!req.file) return res.status(400).json({ message: 'Bukti pembayaran wajib diupload' });
        const product = await Course.findByPk(productId);
        if (!product || !product.isActive) return res.status(400).json({ message: 'Produk tidak tersedia' });
        if (product.stock <= 0) return res.status(400).json({ message: 'Stok produk habis' });

        const paymentMethods = await getJsonSetting('payment_methods', defaultPaymentMethods);
        const payment = paymentMethods.find(item => item.id === paymentMethodId && item.isActive !== false);
        if (!payment) return res.status(400).json({ message: 'Metode pembayaran tidak tersedia' });
        const paymentProofUrl = await uploadProofToR2(req.file);

        const tx = await Transaction.create({
            buyerName,
            buyerEmail,
            buyerWhatsapp,
            productId: product.id,
            productTitle: product.title,
            paymentMethod: payment.name,
            paymentAccount: `${payment.number} a.n. ${payment.owner}`,
            paymentProofUrl,
            amount: product.price,
            status: 'PENDING'
        });

        await product.decrement('stock', { by: 1 });

        res.json({
            message: 'Pemesanan berhasil, silakan transfer',
            transaction: tx,
            payment
        });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Admin: Ambil Pengaturan CMS
app.get('/api/admin/settings', authenticateToken, async (req, res) => {
    try {
        const paymentMethods = await getJsonSetting('payment_methods', defaultPaymentMethods);
        const content = await getJsonSetting('landing_content', defaultLanding);
        const products = await Course.findAll({ order: [['id', 'DESC']] });
        res.json({
            paymentMethods,
            content,
            products
        });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Admin: Simpan Pengaturan CMS
app.post('/api/admin/settings', authenticateToken, async (req, res) => {
    const { paymentMethods = [], products = [], content = {} } = req.body;
    try {
        const safeContent = Object.keys(defaultLanding).reduce((result, key) => {
            result[key] = cleanText(content[key] ?? defaultLanding[key], key.includes('Description') || key.includes('Bio') || key.includes('Quote') ? 700 : 180);
            return result;
        }, {});
        const safeProducts = sanitizeProducts(products);
        const safePaymentMethods = sanitizePaymentMethods(paymentMethods);

        if (!safeProducts.length) return res.status(400).json({ message: 'Minimal harus ada 1 produk' });
        if (!safePaymentMethods.length) return res.status(400).json({ message: 'Minimal harus ada 1 metode pembayaran' });

        await Setting.upsert({ key: 'landing_content', value: JSON.stringify(safeContent) });
        await Setting.upsert({ key: 'payment_methods', value: JSON.stringify(safePaymentMethods) });

        const existingProducts = await Course.findAll();
        const incomingIds = safeProducts.map(item => item.id).filter(Boolean);
        const deletableIds = existingProducts.map(item => item.id).filter(id => !incomingIds.includes(id));

        for (const product of safeProducts) {
            const payload = {
                title: product.title,
                description: product.description,
                price: product.price,
                originalPrice: Math.max(product.originalPrice, product.price),
                stock: product.stock,
                benefits: product.benefits,
                isActive: product.isActive
            };
            if (product.id) {
                await Course.update(payload, { where: { id: product.id } });
            } else {
                await Course.create(payload);
            }
        }
        if (deletableIds.length) await Course.destroy({ where: { id: deletableIds } });
        res.json({ message: 'Pengaturan berhasil diperbarui' });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/admin/products', authenticateToken, async (req, res) => {
    try {
        const product = sanitizeProduct(req.body);
        if (!product) return res.status(400).json({ message: 'Data produk tidak valid' });
        const created = await Course.create({
            title: product.title,
            description: product.description,
            price: product.price,
            originalPrice: Math.max(product.originalPrice, product.price),
            stock: product.stock,
            benefits: product.benefits,
            isActive: product.isActive
        });
        res.json({ message: 'Produk berhasil ditambahkan', product: created });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/admin/products/:id', authenticateToken, async (req, res) => {
    try {
        const product = sanitizeProduct({ ...req.body, id: req.params.id });
        if (!product) return res.status(400).json({ message: 'Data produk tidak valid' });
        const [updated] = await Course.update({
            title: product.title,
            description: product.description,
            price: product.price,
            originalPrice: Math.max(product.originalPrice, product.price),
            stock: product.stock,
            benefits: product.benefits,
            isActive: product.isActive
        }, { where: { id: req.params.id } });
        if (!updated) return res.status(404).json({ message: 'Produk tidak ditemukan' });
        const saved = await Course.findByPk(req.params.id);
        res.json({ message: 'Produk berhasil diperbarui', product: saved });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/admin/products/:id', authenticateToken, async (req, res) => {
    try {
        const deleted = await Course.destroy({ where: { id: req.params.id } });
        if (!deleted) return res.status(404).json({ message: 'Produk tidak ditemukan' });
        res.json({ message: 'Produk berhasil dihapus' });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Admin: Ambil Transaksi (Search, Limit, Pagination Lengkap)
app.get('/api/admin/transactions', authenticateToken, async (req, res) => {
    let { page, limit, search, status } = req.query;
    page = parseInt(page) || 1;
    limit = Math.min(parseInt(limit) || 10, 100);
    const offset = (page - 1) * limit;

    let whereClause = {};
    if (search) {
        whereClause = {
            [Op.or]: [
                { buyerName: { [Op.like]: `%${search}%` } },
                { buyerEmail: { [Op.like]: `%${search}%` } },
                { buyerWhatsapp: { [Op.like]: `%${search}%` } },
                { productTitle: { [Op.like]: `%${search}%` } },
                { paymentMethod: { [Op.like]: `%${search}%` } }
            ]
        };
    }
    if (['PENDING', 'APPROVED', 'REJECTED'].includes(status)) whereClause.status = status;

    try {
        const { count, rows } = await Transaction.findAndCountAll({
            where: whereClause,
            limit,
            offset,
            order: [['createdAt', 'DESC']]
        });
        res.json({
            totalItems: count,
            totalPages: Math.ceil(count / limit),
            currentPage: page,
            data: rows
        });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Admin: Aksi Ganti Status Transaksi
app.patch('/api/admin/transactions/:id', authenticateToken, async (req, res) => {
    try {
        if (!['PENDING', 'APPROVED', 'REJECTED'].includes(req.body.status)) {
            return res.status(400).json({ message: 'Status tidak valid' });
        }
        const [updated] = await Transaction.update({ status: req.body.status }, { where: { id: req.params.id } });
        if (!updated) return res.status(404).json({ message: 'Transaksi tidak ditemukan' });
        res.json({ message: 'Status transaksi berhasil diperbarui' });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Admin: Dashboard Analytics (100% DINAMIS DARI DATABASE)
app.get('/api/admin/dashboard-stats', authenticateToken, async (req, res) => {
    try {
        // 1. Hitung Total Omset Riil (Hanya yang APPROVED)
        const totalRevenue = await Transaction.sum('amount', { where: { status: 'APPROVED' } }) || 0;
        
        // 2. Hitung Total Pesanan Masuk (Semua Status)
        const totalOrders = await Transaction.count();
        const pendingOrders = await Transaction.count({ where: { status: 'PENDING' } });
        const approvedOrders = await Transaction.count({ where: { status: 'APPROVED' } });

        // 3. Ambil data transaksi 6 bulan terakhir secara dinamis
        const statsData = await Transaction.findAll({
            attributes: [
                [sequelize.fn('DATE_FORMAT', sequelize.col('createdAt'), '%Y-%m'), 'period'],
                [sequelize.fn('DATE_FORMAT', sequelize.col('createdAt'), '%b %Y'), 'month'],
                [sequelize.fn('SUM', sequelize.literal("CASE WHEN status = 'APPROVED' THEN amount ELSE 0 END")), 'revenue'],
                [sequelize.fn('COUNT', sequelize.col('id')), 'total_tx'],
                [sequelize.fn('SUM', sequelize.literal("CASE WHEN status = 'APPROVED' THEN 1 ELSE 0 END")), 'approved_tx']
            ],
            group: ['period', 'month'],
            order: [[sequelize.literal('period'), 'DESC']],
            limit: 6
        });

        // Map data database ke dalam array untuk dikonsumsi Chart.js
        let months = [];
        let revenue = [];
        let transactionsCount = [];
        let conversionRate = [];

        if (statsData.length > 0) {
            statsData.reverse().forEach(item => {
                const monthName = item.getDataValue('month');
                const rev = parseInt(item.getDataValue('revenue')) || 0;
                const total = parseInt(item.getDataValue('total_tx')) || 0;
                const approved = parseInt(item.getDataValue('approved_tx')) || 0;
                
                // Hitung Rasio Konversi ( % ) riil
                const rate = total > 0 ? Math.round((approved / total) * 100) : 0;

                months.push(monthName);
                revenue.push(rev);
                transactionsCount.push(total);
                conversionRate.push(rate);
            });
        } else {
            // Fallback jika database masih kosong agar chart tidak error ter-render kosong
            months = ['No Data'];
            revenue = [0];
            transactionsCount = [0];
            conversionRate = [0];
        }

        res.json({
            totalRevenue,
            totalOrders,
            pendingOrders,
            conversionRateTotal: totalOrders ? Math.round((approvedOrders / totalOrders) * 100) : 0,
            months,
            revenue,
            transactionsCount,
            conversionRate
        });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.use((err, req, res, next) => {
    if (err instanceof multer.MulterError) {
        if (err.code === 'LIMIT_FILE_SIZE') return res.status(400).json({ message: 'Ukuran bukti pembayaran maksimal 5MB' });
        return res.status(400).json({ message: err.message });
    }
    if (err && err.message === 'Bukti pembayaran harus berupa gambar') {
        return res.status(400).json({ message: err.message });
    }
    return next(err);
});

// Wildcard Fallback Route
app.use((req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// --- INITIALIZE SYSTEM ---
const PORT = Number(process.env.PORT) || 20626;
sequelize.sync({ alter: true }).then(async () => {
    // Memastikan User Default Terbuat saat awal sistem jalan
    const userExist = await User.findOne({ where: { username: 'admin' } });
    if (!userExist) {
        const hashedPassword = await bcrypt.hash('admin123', 10);
        await User.create({ username: 'admin', password: hashedPassword });
        console.log('======================================================');
        console.log('==> CMS Default Akun: User: admin | Pass: admin123 <==');
        console.log('======================================================');
    }
    const courseExists = await Course.count();
    if (!courseExists) {
        await Course.create({
            title: 'AI Product Builder',
            description: 'Kelas praktis membangun produk digital dengan bantuan AI.',
            price: 349000,
            originalPrice: 499000,
            stock: 25,
            benefits: 'Fondasi prompt yang efektif,Workflow otomasi bisnis,Membangun aplikasi dengan AI,Deploy produk ke internet,Template siap pakai,Akses komunitas belajar'
        });
    }
    const paymentMethods = await Setting.findOne({ where: { key: 'payment_methods' } });
    if (!paymentMethods) {
        await Setting.create({ key: 'payment_methods', value: JSON.stringify(defaultPaymentMethods) });
    }
    app.listen(PORT, () => console.log(`Server berjalan di http://localhost:${PORT}`));
}).catch(err => {
    console.error('Gagal menginisialisasi aplikasi:', err.message);
    process.exit(1);
});
