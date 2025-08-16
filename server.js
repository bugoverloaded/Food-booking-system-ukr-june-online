// server.js
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const cors = require('cors');
const http = require('http');
const { Server } = require('socket.io');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const JWT_SECRET = 'supersecretkey';
const PORT = 5000;

// --- MongoDB Connection ---
mongoose.connect('mongodb://127.0.0.1:27017/foodexpress', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
})
.then(()=>console.log('MongoDB connected'))
.catch(err=>console.log(err));

// --- Schemas ---
const userSchema = new mongoose.Schema({
    name: String,
    email: { type:String, unique:true },
    password: String,
    phone: String,
    address: String,
    role: { type:String, default:'user' },
});
const User = mongoose.model('User', userSchema);

const adminSchema = new mongoose.Schema({
    name: String,
    email: { type:String, unique:true },
    password: String,
    role: { type:String, default:'admin' },
});
const Admin = mongoose.model('Admin', adminSchema);

const restaurantSchema = new mongoose.Schema({
    name: String,
    email: { type:String, unique:true },
    phone: String,
    address: String,
    logo: String,
});
const Restaurant = mongoose.model('Restaurant', restaurantSchema);

const menuSchema = new mongoose.Schema({
    restaurant: { type: mongoose.Schema.Types.ObjectId, ref:'Restaurant' },
    name: String,
    category: { type:String, enum:['Veg','Non-Veg','Beverages','Desserts'] },
    price: Number,
    description: String,
    image: String,
});
const Menu = mongoose.model('Menu', menuSchema);

const orderSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref:'User' },
    items: [{ menu:{ type: mongoose.Schema.Types.ObjectId, ref:'Menu' }, quantity:Number }],
    totalPrice: Number,
    status: { type:String, enum:['Preparing','Out for delivery','Delivered'], default:'Preparing' },
    deliverySlot: String,
    paymentMethod: { type:String, enum:['COD','Stripe','Razorpay','UPI'], default:'COD' },
}, { timestamps:true });
const Order = mongoose.model('Order', orderSchema);

// --- Auth Routes ---
// Register
app.post('/auth/register', async(req,res)=>{
    try{
        const { name,email,password,phone,address } = req.body;
        const hashed = await bcrypt.hash(password,10);
        const user = new User({ name,email,password:hashed,phone,address });
        await user.save();
        res.json({ message:'User registered' });
    } catch(e){ res.status(400).json({ error:e.message }); }
});

// Login
app.post('/auth/login', async(req,res)=>{
    try{
        const { email,password } = req.body;
        let user = await User.findOne({ email });
        if(!user) user = await Admin.findOne({ email });
        if(!user) return res.status(400).json({ error:'User not found' });
        const match = await bcrypt.compare(password,user.password);
        if(!match) return res.status(400).json({ error:'Invalid password' });
        const token = jwt.sign({ id:user._id, role:user.role }, JWT_SECRET, { expiresIn:'7d' });
        res.json({ token, role:user.role });
    } catch(e){ res.status(500).json({ error:e.message }); }
});

// Middleware for auth
function authMiddleware(req,res,next){
    const token = req.headers['authorization'];
    if(!token) return res.status(401).json({ error:'No token' });
    try{
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch(e){ res.status(401).json({ error:'Invalid token' }); }
}

// --- Menu Routes ---
app.get('/menu', async(req,res)=>{ 
    const menu = await Menu.find().populate('restaurant'); 
    res.json(menu);
});

app.post('/menu', authMiddleware, async(req,res)=>{
    if(req.user.role!=='admin') return res.status(403).json({ error:'Admin only' });
    const { restaurantId,name,category,price,description,image } = req.body;
    const menu = new Menu({ restaurant:restaurantId,name,category,price,description,image });
    await menu.save();
    res.json(menu);
});

app.put('/menu/:id', authMiddleware, async(req,res)=>{
    if(req.user.role!=='admin') return res.status(403).json({ error:'Admin only' });
    const menu = await Menu.findByIdAndUpdate(req.params.id, req.body,{ new:true });
    res.json(menu);
});

app.delete('/menu/:id', authMiddleware, async(req,res)=>{
    if(req.user.role!=='admin') return res.status(403).json({ error:'Admin only' });
    await Menu.findByIdAndDelete(req.params.id);
    res.json({ message:'Deleted' });
});

// --- Order Routes ---
app.post('/order', authMiddleware, async(req,res)=>{
    const { items, deliverySlot, paymentMethod } = req.body;
    let total = 0;
    for(const it of items){
        const menuItem = await Menu.findById(it.menu);
        total += menuItem.price * it.quantity;
    }
    const order = new Order({ user:req.user.id, items, totalPrice:total, deliverySlot, paymentMethod });
    await order.save();
    io.emit('newOrder', order); // Socket notification
    res.json(order);
});

app.get('/order', authMiddleware, async(req,res)=>{
    let orders;
    if(req.user.role==='admin') orders = await Order.find().populate('items.menu').populate('user');
    else orders = await Order.find({ user:req.user.id }).populate('items.menu');
    res.json(orders);
});

app.put('/order/:id/status', authMiddleware, async(req,res)=>{
    if(req.user.role!=='admin') return res.status(403).json({ error:'Admin only' });
    const { status } = req.body;
    const order = await Order.findByIdAndUpdate(req.params.id, { status }, { new:true }).populate('items.menu').populate('user');
    io.emit('orderStatus', order); // real-time update
    sendOrderEmail(order.user.email, `Order ${order._id} Status Updated`, `Status: ${status}`);
    res.json(order);
});

// --- Socket.io ---
io.on('connection', socket=>{
    console.log('User connected', socket.id);
    socket.on('joinOrderRoom', orderId => { socket.join(orderId); });
});

// --- NodeMailer Stub ---
const transporter = nodemailer.createTransport({
    service:'gmail',
    auth:{ user:'your-email@gmail.com', pass:'your-app-password' }
});
function sendOrderEmail(to,subject,text){
    console.log(`Email to ${to}: ${subject} - ${text}`);
    // transporter.sendMail({ from:'FoodExpress <your-email@gmail.com>', to, subject, text });
}

// --- Start Server ---
server.listen(PORT,()=>console.log(`Server running on http://localhost:${PORT}`));
