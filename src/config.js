const mongoose = require('mongoose')
const connect = mongoose.connect("mongodb://localhost:27017/clothing_store")


connect.then(() => {
    console.log("Database connected successfully!");
})
connect.catch(() => {
    console.log("Failed to connect database!");
})


// create schema
const authSchema = new mongoose.Schema({
    name: String,
    email: String,
    password: String
});

const itemSchema = new mongoose.Schema({
    name: { type: String, required: true},
    detail: String,
    selling_price: { type: Number, required: true},
    discounted_price: Number,
    size: String,
    color: String,
    stock: { type:Number, default: 0},
    category: String,
    image: String
});

const tokenScehma = new mongoose.Schema({ 
    tokens: { type: String, required: true } 
});

// create collection
const customerCollection = mongoose.model("customers", authSchema);
const itemCollection = mongoose.model("items", itemSchema);
const tokenCollection = mongoose.model("tokens", tokenScehma);

module.exports = { customerCollection, itemCollection, tokenCollection};

