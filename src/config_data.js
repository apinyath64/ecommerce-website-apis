const mongoose = require('mongoose')
const connect = mongoose.connect("mongodb://localhost:27017/clothing_store")

connect.then(() => {
    console.log("Database connect successfully for config_data");
})

connect.catch(() => {
    console.log("Failed to connect to database!");
})


