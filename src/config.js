const { name } = require('ejs');
const mongoose = require('mongoose')
const connect = mongoose.connect("mongodb://localhost:27017/clothing_store")


connect.then(() => {
    console.log("Database connected successfully!");
})
connect.catch(() => {
    console.log("Failed to connect database!");
})


// create schema
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true, trim: true},
    email: { type: String, required: true, unique: true, trim: true },
    password: { type: String, required: true },
    role: { type: String, enum: ["customer", "admin"], default: "customer" }
}); 

const itemSchema = new mongoose.Schema({
    name: { type: String, required: true},
    detail: String,
    selling_price: { type: Number, required: true},
    discounted_price: { type: Number, default: 0 },
    size: String,
    color: String,
    stock: { type:Number, default: 0},
    category: String,
    image: String
});

const cartSchema = new mongoose.Schema({
    customer: { type: mongoose.Schema.Types.ObjectId, ref: 'customers'},
    item: { type: mongoose.Schema.Types.ObjectId, ref: 'items' },
    quantity: { type: Number, default: 1 }
});


const addressSchema = new mongoose.Schema({
    customer: { type: mongoose.Schema.Types.ObjectId, ref: 'customers' },
    fullName: { type: String, required: true },
    phoneNumber: { type: String, required: true },
    province: { type: String, required: true },
    district: { type: String, required: true },
    subdistrict: { type: String, required: true },
    postalCode: { type: String, required: true },
    address: { type: String, required: true },
    label: { type: String, enum: ["home", "office"], default: "home" }
});


const paymentSchema = mongoose.Schema({
    customer: { type: mongoose.Schema.Types.ObjectId, ref: "customers", required: true },
    amount: { type: Number, required: true },
    currency: { type: String, default: 'thb' },
    charge_id: { type: String, required: true },
    payment_method: { type: String, enum: ["credit_card", "promptpay"], default: "credit_card", required: true },
    payment_status: { type: String, enum: ["pending", "successful", "failed"], default: "pending" },
    is_paid: { type: Boolean, default: false }
});


const orderSchema = mongoose.Schema({
    customer: { type: mongoose.Schema.Types.ObjectId, ref: 'customers', required: true },
    address: { type: mongoose.Schema.Types.ObjectId, ref: 'addresses' },
    items: [{
        item: {type: mongoose.Schema.Types.ObjectId, ref: 'items' },
        quantity: { type: Number, default: 1 }
    }],
    order_date: { type: Date, default: Date.now },
    order_status: { type: String, 
        enum: ["Accepted", "Packed", "On the Way", "Delivered", "Cancel", "Pending"], 
        default: "Pending" 
    },
    payment: {type: mongoose.Schema.Types.ObjectId, ref: "payments" },
    shipping_method: { type: mongoose.Schema.Types.ObjectId, ref: 'shippings', required: true }

});

const shippingSchema = mongoose.Schema({
    id: { type: String, required: true },
    name: { type: String, required: true },
    price: { type: Number, required: true },
    estimated: { type: String, required: true },
    is_default: { type: Boolean, default: false }
})

const favoriteSchema = mongoose.Schema({
    customer: { type: mongoose.Schema.Types.ObjectId, ref: 'customers', required: true },
    item: { type: mongoose.Schema.Types.ObjectId, ref: 'items' }
})


const tokenScehma = new mongoose.Schema({ 
    tokens: { type: String, required: true } 
});

// create collection
const customerCollection = mongoose.model("customers", userSchema)
const itemCollection = mongoose.model("items", itemSchema)
const tokenCollection = mongoose.model("tokens", tokenScehma)
const cartCollection = mongoose.model("carts", cartSchema)
const addressCollection = mongoose.model("addresses", addressSchema)
const paymentCollection = mongoose.model("payments", paymentSchema)
const orderCollection = mongoose.model("orders", orderSchema)
const favoriteCollection = mongoose.model("favorites", favoriteSchema)
const shippingCollection = mongoose.model("shippings", shippingSchema)


module.exports = { 
    customerCollection, 
    itemCollection, 
    tokenCollection, 
    cartCollection, 
    addressCollection,
    paymentCollection,
    orderCollection,
    favoriteCollection,
    shippingCollection
};

