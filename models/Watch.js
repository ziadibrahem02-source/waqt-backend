const mongoose = require('mongoose');

const watchSchema = new mongoose.Schema({
    nameAr: { type: String, required: true },
    nameEn: { type: String, required: true },
    price: { type: Number, required: true }, // السعر الحقيقي اللي هنعتمد عليه
    descAr: { type: String, required: true },
    descEn: { type: String, required: true },
    images: [{ type: String }], // مصفوفة لروابط الصور
    createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Watch', watchSchema);