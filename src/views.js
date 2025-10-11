require('dotenv').config()

const express = require('express')
const cookieParser = require('cookie-parser');
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

const collection = require('./config')
const { name } = require('ejs')

const omise = require('omise')({
    'publicKey': process.env.OMISE_PUBLIC_KEY, 
    'secretKey': process.env.OMISE_SECRET_KEY
})

const app = express()

app.set("view engine", "ejs")

app.use(express.json())
app.use(express.static("static"))
app.use(cookieParser())


// Authentication
app.get('/login', (req, res) => {
    res.render("login")
})

app.get('/signup', (req, res) => {
    res.render("signup")
})

app.post('/signup', async (req, res) => {
    const data = {
        username: req.body.username,
        email: req.body.email,
        password: req.body.password,
        confirm_password: req.body.confirm_password,
        role: req.body.role 
    }

    // check user exist
    const userExist = await collection.customerCollection.findOne({ username: data.username })

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
                username: data.username,
                email: data.email,
                password: data.password,
                role: data.role
            });
            return res.status(201).send("สมัครสมาชิกเรียบร้อยแล้ว")
        }
    }
});

app.post('/login', async (req, res) => {
    try {
        const users = await collection.customerCollection.findOne({ username: req.body.username })
        if (!users) {
            return res.status(404).send("ไม่มีผู้ใช้ชื่อนี้อยู่")
        }
        const isPasswordMatch = await bcrypt.compare(req.body.password, users.password)
        if (isPasswordMatch) {
            // สร้าง accesstoken
            const user = { username: users.username, id: users.id }
            
            const accessToken = generateAccessToken(user)
            const refreshToken = jwt.sign(user, process.env.REFRESH_TOKEN_SECRET)
        
            await collection.tokenCollection.insertOne({ tokens: refreshToken})
            
            // ส่ง refresh token ไปที่ cookie
            res.cookie("refreshToken", refreshToken, {
                httpOnly: true,
                secure: true,
                sameSite: "strict"  //ป้องกัน CSRF attack
            })

            res.json({ accessToken: accessToken, refreshToken: refreshToken })
            // res.render("home")
        } else {
            return res.status(400).send("รหัสผ่านไม่ถูกต้อง")
        }
        
    } catch (error) {
        console.log(error.message);
        
        return res.status(500).send("ข้อมูลไม่ถูกต้อง")
    }
});

app.post('/logout', authenticateToken, async (req, res) => {
    try {
        const refreshToken = req.cookies.refreshToken

        if (!refreshToken) {
            return res.status(400).send("ไม่พบ token")
        }

        await collection.tokenCollection.deleteOne({ tokens: refreshToken })
        res.clearCookie("refreshToken", { 
            httpOnly: true,
            secure: true,
            sameSite: "strict" })
        
        return res.status(200).send("ออกจากระบบเรียบร้อยแล้ว")

    } catch (error) {
        console.log("Logout error", error);
        return res.status(500).send("เกิดข้อผิดพลาดในระหว่างออกจากระบบ")
    }

})

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
        const accessToken = generateAccessToken({ username: user.username, id: user.id })
        return res.json({ accessToken: accessToken })
    });
});


app.get('/home', (req, res) => {
    res.render("home")
})

// get user informations
app.get('/users/profile', authenticateToken, async (req, res) => {
    try {
        const req_user = await collection.customerCollection.findById(req.user.id)
        if (!req_user) {
            return res.status(404).send("ไม่มีผู้ใช้นี้อยู่")
        }

        const { id, username, email } = req_user

        return res.status(200).json({ user: { id, username, email }})

    } catch (error) {
        console.log("Profile error: ", error.message);
        return res.status(500).send("เกิดข้อผิดพลาดภายในระบบ")
    }
})

// update user info
app.put('/users/profile', authenticateToken, async (req, res) => {
    const { username, email } = req.body

    try {
        const req_user = await collection.customerCollection.findById(req.user.id)
        if (!req_user) {
            return res.status(404).send("ไม่มีผู้ใช้นี้อยู่")
        }

        // check if username and email exist
        const username_exist = await collection.customerCollection.findOne({ 
            username: username,
            _id: { $ne: req.user.id }  //ไม่รวมผู้ใช้ปัจจุบัน
        })

        if (username_exist) {
            return res.status(400).send("มีชื่อผู้ใช้นี้อยู่แล้ว กรุณาเลือกชื่อผู้ใช้ใหม่")
        }

        const email_exist = await collection.customerCollection.findOne({
            email: email,
            _id: { $ne: req.user.id }
        })

        if (email_exist) {
            return res.status(400).send("มีอีเมลนี้อยู่แล้ว กรุณาเลือกอีเมลใหม่")
        }

        if (username !== undefined) req_user.username = username
        if (email !== undefined) req_user.email = email
        await req_user.save()

        const user = {
            id: req.user.id,
            username: req_user.username,
            email: req_user.email
        }

        return res.status(200).json({ message: "แก้ไขข้อมูลผู้ใช้สำเร็จ", user })

    } catch (error) {
        console.log("Update profile error: ", error);
        return res.status(500).send("เกิดข้อผิดพลาดภายในระบบ")
    }
})

// add item
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

app.get('/items', async (req, res) => {
    const item = await collection.itemCollection.find({})
    return res.json({item: item})
})


app.get('/items/:id', async (req, res) => {
    const { id } = req.params
    const item = await collection.itemCollection.findById(id)
    return res.json(item)
})


app.put('/items/:id', authenticateToken, async (req, res) => {
    const { id } = req.params
    const { name, detail, selling_price, discounted_price, size, color, stock, category, image} = req.body
    
    const item = await collection.itemCollection.findById(id)
    if (!item) {
        return res.status(404).send("ไม่มีรายการนี้อยู่")
    }

    // check if no name, selling price / selling price not null/num
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


// delete item
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


app.get('/cart', authenticateToken, async (req, res) => {
    const user_id = req.user.id

    // populate ใช้แทน obj ref ด้วย document จริง
    const cart = await collection.cartCollection.find({ customer: user_id }).populate('item').populate('customer')
    
    if (cart === null) {
        return res.send("ยังไม่มีรายการ")
    }

    const data = cart.map(c => ({
        id: c.id,
        itemId: c.item.id,
        itemName: c.item.name,
        customerId: c.customer.id,
        customerName: c.customer.username,
        quantity: c.quantity
    }))

    return res.status(200).json(data)
})

// add to cart
app.post('/cart/:item_id', authenticateToken, async (req, res) => {
    const { item_id } = req.params
    const user = req.user.id

    const cart = await collection.cartCollection.insertOne({ customer: user, item: item_id })
    if (!cart) {
        return res.status(400).send("ไม่สามารถเพิ่มรายการได้")
    }

    return res.status(201).json({ message: "เพิ่มรายการสำเร็จ", cart: cart })
})


// increse item
app.post('/cart/items/:item_id/increase', authenticateToken, async (req, res) => {
    const { item_id } = req.params
    const user = req.user.id

    try {
        const cart = await collection.cartCollection.findOne({ customer: user, item: item_id })

        if (!cart) {
            return res.status(400).send("ไม่มีรายการนี้อยู่")
        } 
        cart.quantity += 1    
        await cart.save()

        return res.status(200).json({ cart })
    } catch (error) {
        console.log(error.message);
        return res.status(500).send("ไม่สามารถเพิ่มจำนวนรายการได้")
    }
})

// decrease item
app.post('/cart/items/:item_id/decrease', authenticateToken, async (req, res) => {
    const { item_id } = req.params
    const user = req.user.id

    try {
        const cart = await collection.cartCollection.findOne({ customer: user, item: item_id })

        if (!cart) {
            return res.status(400).send("ไม่มีรายการนี้อยู่")
        }

        if (cart.quantity > 1) {
            cart.quantity -= 1
            await cart.save()
        } else {
            return res.status(400).send("ไม่สามารถลดจำนวนรายการได้")
        }

        return res.status(200).json({ cart })
    } catch (error) {
        console.log(error.message);
        return res.status(500).send("ไม่สามารถลดจำนวนรายการได้")
    }

})

// remove from cart
app.delete('/cart/items/:item_id', authenticateToken, async (req,res) => {
    const { item_id } = req.params

    const user = req.user.id

    const cart = await collection.cartCollection.findOne({ customer: user, item: item_id })

    if (!cart) {
        return res.status(404).send("ไม่พบรายการ")        
    }

    await cart.deleteOne()
    
    return res.status(204).send()
})


// add new address
app.post('/address',authenticateToken, async (req, res) => {
    
    const data = {
        customer: req.user.id,
        fullName: req.body.fullName,
        phoneNumber: req.body.phoneNumber,
        province: req.body.province,
        district: req.body.district,
        subdistrict: req.body.subdistrict,
        postalCode: req.body.postalCode,
        address: req.body.address,
        label: req.body.label
    }

    try {
        const query = `${data.district}+${data.province}+${data.postalCode}+Thailand`;
        const url = `https://nominatim.openstreetmap.org/search?q=${query}&format=json`;
        console.log(url);
        
        const response = await fetch(url, {
            headers: { "User-Agent": "ecommerce_api/1.0 (apinya.tho.64@ubu.ac.th)" }
        })

        if (!response.ok) {
            return res.status(502).json({ error: "ไม่สามารถระบุตำแหน่งได้" })
        }

        const result = await response.json();

        if (result.length === 0) {
            return res.status(400).json({ error: "ที่อยู่ไม่ถูกต้อง กรุณาตรวจสอบอีกครั้ง" })
        }

        const addresses = await collection.addressCollection.insertOne(data);

        return res.status(201).json({ message: "บันทึกที่อยู่สำเร็จ", addresses: addresses });

    } catch (err) {
        console.error(err);
        return res.status(500).json({ error: "Server error" })
   
    }
});

// checkout
app.get('/checkout', authenticateToken, async (req, res) => {
    const user = req.user.id

    try {
        const cart = await collection.cartCollection.find({ customer: user }).populate('item')

        // delivery addresses
        const address = await collection.addressCollection.find({ customer: user })

        // shipping options
        const shipping = await collection.shippingCollection.find({})

        let payment_total = 0
        let saving_total = 0

        for (c of cart) {
            let saving = 0
            let total = 0  //ราคายังไม่รวม shipping price

            if (c.item.discounted_price === 0) {
                total = c.quantity * c.item.selling_price 
                saving = 0
            } else {
                total =  c.quantity * c.item.discounted_price
                saving = (c.quantity * c.item.selling_price) - total
            }
            saving_total = saving_total + saving
            payment_total = payment_total + total
            
        }

        const data = {
            items: cart,
            adress: address,
            shippingOptions: shipping,
            paymentMethods: [],
            savingTotal: saving_total,
            paymentTotal: payment_total

        }
        return res.status(200).json({data})

    } catch (error) {
        console.log(error.message)
        return res.status(500).send("เกิดข้อผิดพลาดจากเซิร์ฟเวอร์ กรุณาลองใหม่อีกครั้ง")
    }
});


app.post('/checkout', authenticateToken, async (req, res) => {
    const user = req.user.id
    const { payment_method, address_id, omise_token, shipping_method } = req.body

    try {

        const cart = await collection.cartCollection.find({ customer: user }).populate('item')
        const address = await collection.addressCollection.findById(address_id)
        let selected_shipping = await collection.shippingCollection.findOne({ id: shipping_method })
        
        if (!selected_shipping) {
            selected_shipping = await collection.shippingCollection.findOne({ is_default: true })
            // return res.status(400).send("กรุณาเลือกวิธีการจัดส่ง")
        }

        if (!address) {
            return res.status(400).send("กรุณาเพิ่มที่อยู่!")
        }

        if (!omise_token) {
            return res.status(400).send("ไม่สามารถชำระเงินได้!")
        }


        let amount = 0
        for (c of cart) {
            let total = 0
            if (c.item.discounted_price === 0) {
                total = c.quantity * c.item.selling_price
            } else {
                total = c.quantity * c.item.discounted_price
            }
            amount += total
        }

        amount += selected_shipping.price
        
        console.log(amount);
        console.log(selected_shipping.price);
        

        // create charge
        const charge = omise.charges.create({
            "amount": amount*100,
            "currency": "thb",
            "card": omise_token
        })

        if ((await charge).status === "successful" ) {
            console.log("create charge successfully");
            
            // create payment obj
            const payment = await collection.paymentCollection.create({
                customer: user,
                amount: amount,
                currency: 'thb',
                charge_id: (await charge).id,
                payment_status: (await charge).status,
                is_paid: true
            })
            console.log(payment);

            // create order
            const order = await collection.orderCollection.create({
                customer: user,
                address: address,
                items: cart.map(c => ({
                    item: c.item,
                    quantity: c.quantity
                })),
                payment: payment._id,
                shipping_method: selected_shipping._id
            })
            await collection.cartCollection.deleteMany({ customer: user })
        
            return res.status(201).json({ message: "จ่ายเงินสำเร็จ", order: order })

            
        } else {
            console.log(error.message);
            return res.status(400).send("จ่ายเงินไม่สำเร็จ!")
        }

    } catch (error) {
        console.log(error.message);
        return res.status(500).json({ message: "จ่ายเงินไม่สำเร็จ!" })
        
    }
    
})

// omise token for payment testing
app.post('/omise-token', async (req, res) => {
    const { name, 
        number, 
        expiration_month, 
        expiration_year, 
        security_code, 
        country 
    } = req.body

    try {
        const token = await omise.tokens.create({
            card: {
                name: name,
                number: number,
                expiration_month: expiration_month,
                expiration_year: expiration_year,
                security_code: security_code,
                country: country
            }
        })
        console.log(token.id);

        return res.status(201).json({ token: token.id })
    } catch (err) {
        console.log(err.message);
        return res.status(500).json({ message: "Can not create token!" })
        
    }
})


app.get('/order', authenticateToken, async (req, res) => {
    const user = req.user.id
    try {
        const order = await collection.orderCollection.find({ customer: user })
        .populate('address')
        .populate('payment')
        .populate('items.item')

        res.status(200).json({ order })

    } catch (error) {
        console.log(error.message);
        return res.status(500).send()
    }
})

// favorites
app.get('/favorites', authenticateToken, async (req, res) => {
    const user = req.user.id
    
    try {
        const favorites = await collection.favoriteCollection.find({ customer: user }).populate('item')
  
        if (favorites.length === 0) {
            return res.status(400).send("ไม่พบรายการสิ่งที่อยากได้")  
        } 
        return res.status(200).json({ favorites })

    } catch (error) {
        console.log(error)
        return res.status(500).send("เกิดข้อผิดพลาดจากเซิร์ฟเวอร์ กรุณาลองใหม่อีกครั้ง")
    }

})

app.post('/favorites/:item_id', authenticateToken, async (req, res) => {
    const user = req.user.id
    const { item_id } = req.params

    try {
        const item = await collection.itemCollection.findById(item_id)

        if (!item) {
            return res.status(400).send("ไม่พบรายการที่ระบุ")
        }

        const is_exist = await collection.favoriteCollection.findOne({ customer: user, item: item })
        if (is_exist) {
            return res.status(400).send("ไม่สามารถเพิ่มรายการซ้ำได้")
        }

        const favorites = await collection.favoriteCollection.insertOne({ customer: user, item: item })    
        
        return res.status(201).json({message: "เพิ่มรายการสิ่งที่อยากได้สำเร็จ", favorites})

    } catch (error) {
        console.log(error.message)
        return res.status(500).send("เกิดข้อผิดพลาดจากเซิร์ฟเวอร์ กรุณาลองใหม่อีกครั้ง")
    }

})

app.delete('/favorites/:item_id', authenticateToken, async (req, res) => {
    const { item_id } = req.params
    const user = req.user.id

    try {
        const favorites = await collection.favoriteCollection.findOne({ customer: user, item: item_id })

        if (!favorites) {
            return res.status(404).send("ไม่พบรายการที่ระบุ")
        }
        
        await favorites.deleteOne()
        return res.status(204).send()

    } catch (error) {
        console.log(error.message)
        return res.status(500).send("เกิดข้อผิดพลาดจากเซิร์ฟเวอร์ กรุณาลองใหม่อีกครั้ง")
        
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

function generateAccessToken(user) {
    return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '15m'})
};


const PORT = 4000
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
    
})