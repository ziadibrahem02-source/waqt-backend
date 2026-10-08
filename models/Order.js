const mongoose = require('mongoose');

const orderItemSchema = new mongoose.Schema({
    watchId: { type: mongoose.Schema.Types.ObjectId, ref: 'Watch', required: true },
    quantity: { type: Number, required: true, min: 1, max: 99 },
    price: { type: Number, required: true, min: 0 }
}, { _id: false });

const orderSchema = new mongoose.Schema({
    items: {
        type: [orderItemSchema],
        default: []
    },
    watchId: { type: mongoose.Schema.Types.ObjectId, ref: 'Watch' },
    totalAmount: { type: Number, required: true, min: 0 },
    customerDetails: {
        name: { type: String, required: true, trim: true, maxlength: 100 },
        email: { type: String, required: true, trim: true, lowercase: true, maxlength: 254 },
        phone1: { type: String, required: true, maxlength: 11 },
        phone2: { type: String, default: '', maxlength: 11 },
        governorate: { type: String, required: true, maxlength: 100 },
        address: { type: String, required: true, maxlength: 500 },
        paymentMethod: { type: String, required: true, enum: ['instapay', 'wallet', 'cod'] },
        notes: { type: String, default: '', maxlength: 500 }
    },
    status: {
        type: String,
        enum: ['pending', 'confirmed', 'shipped', 'delivered', 'cancelled'],
        default: 'pending'
    },
    createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Order', orderSchema);
