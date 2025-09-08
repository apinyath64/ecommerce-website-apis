require('dotenv').config()


const express = require('express')
const bcrypt = require('bcrypt')
const ejs = require('ejs')
const mongoose = require('mongoose')
const collection = require('./config')
const jwt = require('jsonwebtoken')

const app = express()
app.use(express.json())

// set view engin
app.set("view engine", "ejs")

app.use(express.static("static"))
app.use(express.urlencoded({ extended: false }))


app.get('/login', (req, res) => {
    res.render("login")
})

app.get('/signup', (req, res) => {
    res.render("signup")
})

app.post('/signup', async (req, res) => {
    const data = {
        name: req.body.username,
        email: req.body.email,
        password: req.body.password,
        confirm_password: req.body.confirm_password 
    }

    // check user exist
    const userExist = await collection.customerCollection.findOne({ name: data.name })

    if (userExist) {
        res.status(400).send("มีผู้ใช้ชื่อนี้อยู่แล้ว กรุณาเลือกชื่อผู้ใช้อื่น")
    } else {
        // check password pattern
        const regex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
        if (!regex.test(data.password)) {
            return res.status(400).send("รหัสผ่านต้องมีอย่างน้อย 8 ตัวอักษร ประกอบด้วยตัวพิมพ์ใหญ่ ตัวพิมพ์เล็ก ตัวเลข และอักขระพิเศษ(@$!%*?&)")
        }

        if (data.password !== data.confirm_password) {
            return res.status(400).send("รหัสผ่านไม่ตรงกัน!")
        } else {
            const salt = 10
            const hashedPassword = await bcrypt.hash(data.password, salt)
            data.password = hashedPassword

            customer = await collection.customerCollection.insertMany({
                name: data.name,
                email: data.email,
                password: data.password,
            });
            return res.status(201).send("สมัครสมาชิกเรียบร้อยแล้ว")
        }
    }
});


app.post('/login', async (req, res) => {
    try {
        const users = await collection.customerCollection.findOne({ name: req.body.username })
        if (!users) {
            return res.status(404).send("ไม่มีผู้ใช้ชื่อนี้อยู่")
        }
        const isPasswordMatch = await bcrypt.compare(req.body.password, users.password)
        if (isPasswordMatch) {
            // สร้าง accesstoken
            const user = { name: users.username }
            const accessToken = generateAccessToken(user)

    
            const refreshToken = jwt.sign(user, process.env.REFRESH_TOKEN_SECRET)
            await collection.tokenCollection.insertOne({ tokens: refreshToken})
            
            res.json({ accessToken: accessToken, refreshToken: refreshToken })
            // res.render("home")
        } else {
            return res.status(400).send("รหัสผ่านไม่ถูกต้อง")
        }
        
    } catch{
        return res.status(400).send("ข้อมูลไม่ถูกต้อง")
    }
});


// route for refresh token
app.post('/refresh', async (req,res) => {
    // get token from body
    const refreshToken = req.body.tokens
    if (!refreshToken) {
        return res.status(401).send("ไม่ได้ยืนยันตัวตน")
    }
    const tokenCollection = await collection.tokenCollection.findOne({ tokens: refreshToken })
    if (!tokenCollection) {
        return res.status(403).send("ไม่มี token นี้ ไม่ได้รับสิทธิ์ในการเข้าถึง")
    }

    jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
        if (err) {
            console.log(err)
            return res.status(403).send("ไม่ได้รับสิทธิ์ในการเข้าถึง")
        }
        const accessToken = generateAccessToken({ name: user.name })
        return res.json({ accessToken: accessToken })
    });
});


function generateAccessToken(user) {
    return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '30m'})
};



const PORT = 5000
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
})