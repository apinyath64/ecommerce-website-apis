require('dotenv').config()

const express = require('express')
const jwt = require('jsonwebtoken')

const collection = require('./config')

const app = express()

app.set("view engine", "ejs")

app.use(express.json())
app.use(express.static("static"))


app.get('/home', (req, res) => {
    res.render("home")
})

// create
app.post('/items', authenticateToken, async (req, res) => {
    const data = {
        name: req.body.name,
        detail: req.body.detail,
        selling_price: req.body.selling_price,
        discounted_price: req.body.discounted_price,
        size: req.body.size,
        color: req.body.color,
        stock: req.body.stock,
        catogory: req.body.catogory,
        image: req.body.image
    }

    try {
        if (!req.body.name || !req.body.selling_price) {
            return res.status(400).send("กรุณากรอกข้อมูลให้ถูกต้อง!")
        }
        item = await collection.itemCollection.insertMany(data)
        return res.status(201).json({
                message: "เพิ่มรายการสำเร็จ",
                item: item
            })
    } catch {
        return res.status(500).send("เพิ่มรายการไม่สำเร็จ!")
    }

});

// read
app.get('/items', async (req, res) => {
    const item = await collection.itemCollection.find({})
    return res.json({item: item})
})


app.get('/items/:id', async (req, res) => {
    const { id } = req.params
    const item = await collection.itemCollection.findById(id)
    return res.json(item)
})


// update
app.put('/items/:id', authenticateToken, async (req, res) => {
    const { id } = req.params
    const { name, detail, selling_price, discounted_price, size, color, stock, category, image} = req.body
    
    const item = await collection.itemCollection.findById(id)
    if (!item) {
        return res.status(404).send("ไม่มีรายการนี้อยู่")
    }

    // check if no name, selling price/ selling price not null/num
    if (!name || selling_price == null || isNaN(selling_price)) { 
        return res.status(400).send("ข้อมูลไม่ถูกต้อง")
    }
    
    item.name  = name
    item.detail = detail
    item.selling_price = selling_price
    item.discounted_price = discounted_price
    item.size = size
    item.color = color
    item.stock = stock
    item.category = category
    item.image = image
    await item.save()

    return res.json({ message: "แก้ไขรายการสำเร็จ", item: item })
})


// delete
app.delete('/items/:id', authenticateToken, async (req, res) => {
    const { id } = req.params
    const item = await collection.itemCollection.findById(id)
    if (!item) {
        return res.status(404).send("ไม่มีรายการนี้อยู่")
    } else {
        await item.deleteOne(item)
        return res.status(204)
    }
})


// middleware for authenticate token
function authenticateToken(req, res, next) {

    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(' ')[1]
    
    if (!token){
        return res.status(401).send("ไม่ได้ยืนยันตัวตน")
    }
    
    // verify token, call back func
    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
        if (err) {
            return res.status(403).send({ message: "ไม่ได้รับสิทธิ์ในการเข้าถึง"})
        }
        req.user = user
        next()
    })

}


const PORT = 4000
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
    
})