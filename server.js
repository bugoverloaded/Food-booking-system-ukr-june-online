// FoodExpress Backend — Node.js + Express + MongoDB + Mongoose + Socket.io
// Includes: Auth, Restaurants & Menu, Orders, Delivery Time Slots, Admin CRUD, Multer uploads, Nodemailer, Stripe & Razorpay integration,
// basic analytics endpoints, and email notifications on order + status updates.
//
// ✅ How to use
// 1) Create a folder, paste these files (preserving paths). Run: `npm install`.
// 2) Set environment variables in `.env` (see example below).
// 3) Start dev server: `npm run dev`. Socket.io will run on same server.
// 4) Open your frontend and point API to `http://localhost:5000/api`.
//
// ─────────────────────────────────────────────────────────────────────────────
// file: package.json
{
  "name": "foodexpress-backend",
  "version": "1.0.0",
  "type": "module",
  "main": "server.js",
  "scripts": {
    "dev": "nodemon server.js",
    "start": "node server.js"
  },
  "dependencies": {
    "bcryptjs": "^2.4.3",
    "cookie-parser": "^1.4.6",
    "cors": "^2.8.5",
    "dotenv": "^16.4.5",
    "express": "^4.19.2",
    "express-validator": "^7.2.1",
    "jsonwebtoken": "^9.0.2",
    "mime-types": "^2.1.35",
    "mongoose": "^8.5.1",
    "multer": "^1.4.5-lts.1",
    "nodemailer": "^6.9.13",
    "razorpay": "^2.9.5",
    "socket.io": "^4.7.5",
    "stripe": "^16.0.0"
  },
  "devDependencies": {
    "nodemon": "^3.1.4"
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// file: .env.example
PORT=5000
MONGO_URI=mongodb://127.0.0.1:27017/foodexpress
JWT_SECRET=supersecret_jwt
CLIENT_ORIGIN=http://localhost:3000

# Email (use Ethereal for dev or your SMTP)
SMTP_HOST=smtp.ethereal.email
SMTP_PORT=587
SMTP_USER=your_ethereal_username
SMTP_PASS=your_ethereal_password
FROM_EMAIL="FoodExpress <no-reply@foodexpress.demo>"

# Stripe (test)
STRIPE_SECRET=sk_test_xxx

# Razorpay (test)
RAZORPAY_KEY_ID=rzp_test_xxx
RAZORPAY_KEY_SECRET=xxx

# Optional public URLs
PUBLIC_URL=http://localhost:5000

// ─────────────────────────────────────────────────────────────────────────────
// file: server.js
import http from 'http';
import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';
import { Server as IOServer } from 'socket.io';
import connectDB from './src/config/db.js';
import { notFound, errorHandler } from './src/middleware/error.js';

// Routes
import authRoutes from './src/routes/auth.routes.js';
import restaurantRoutes from './src/routes/restaurant.routes.js';
import menuRoutes from './src/routes/menu.routes.js';
import orderRoutes from './src/routes/order.routes.js';
import uploadRoutes from './src/routes/upload.routes.js';
import analyticsRoutes from './src/routes/analytics.routes.js';
import paymentRoutes from './src/routes/payment.routes.js';

import { attachIO, getIO } from './src/services/io.js';

dotenv.config();
connectDB();

const app = express();
const server = http.createServer(app);
const io = new IOServer(server, { cors: { origin: process.env.CLIENT_ORIGIN || '*', credentials: true } });
attachIO(io);

app.use(cors({ origin: process.env.CLIENT_ORIGIN || '*', credentials: true }));
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

app.get('/', (req, res) => res.send({ status: 'FoodExpress API running' }));

app.use('/uploads', express.static('uploads'));

app.use('/api/auth', authRoutes);
app.use('/api/restaurants', restaurantRoutes);
app.use('/api/menu', menuRoutes);
app.use('/api/orders', orderRoutes);
app.use('/api/upload', uploadRoutes);
app.use('/api/analytics', analyticsRoutes);
app.use('/api/payment', paymentRoutes);

app.use(notFound);
app.use(errorHandler);

const PORT = process.env.PORT || 5000;
server.listen(PORT, () => console.log(`Server on :${PORT}`));

io.on('connection', (socket) => {
  console.log('Client connected', socket.id);
  socket.on('join-order', (orderId) => socket.join(`order:${orderId}`));
  socket.on('disconnect', () => console.log('Client disconnected', socket.id));
});

// ─────────────────────────────────────────────────────────────────────────────
// file: src/config/db.js
import mongoose from 'mongoose';

export default async function connectDB(){
  try{
    const conn = await mongoose.connect(process.env.MONGO_URI);
    console.log(`MongoDB connected: ${conn.connection.host}`);
  }catch(e){
    console.error('Mongo error', e.message);
    process.exit(1);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// file: src/middleware/auth.js
import jwt from 'jsonwebtoken';
import User from '../models/User.js';

export function protect(roles = []){
  return async (req, res, next) => {
    try{
      const token = req.cookies.token || (req.headers.authorization || '').replace('Bearer ', '');
      if(!token) return res.status(401).json({ message: 'Not authorized' });
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      const user = await User.findById(decoded.id).select('-password');
      if(!user) return res.status(401).json({ message: 'User not found' });
      if(roles.length && !roles.includes(user.role)) return res.status(403).json({ message: 'Forbidden' });
      req.user = user; next();
    }catch(e){ next(e); }
  };
}

export function setAuthCookie(res, token){
  res.cookie('token', token, {
    httpOnly: true,
    sameSite: 'lax',
    secure: false,
    maxAge: 1000 * 60 * 60 * 24 * 7
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// file: src/middleware/error.js
export function notFound(req, res, next){
  res.status(404);
  next(new Error(`Not Found - ${req.originalUrl}`));
}

export function errorHandler(err, req, res, next){
  const status = res.statusCode === 200 ? 500 : res.statusCode;
  res.status(status).json({
    message: err.message || 'Server error',
    stack: process.env.NODE_ENV === 'production' ? '🍳' : err.stack,
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// file: src/models/User.js
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';

const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  phone: { type: String },
  password: { type: String, required: true },
  role: { type: String, enum: ['user', 'admin'], default: 'user' },
  resetToken: String,
  resetTokenExp: Date,
}, { timestamps: true });

userSchema.pre('save', async function(next){
  if(!this.isModified('password')) return next();
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

userSchema.methods.matchPassword = function(pw){ return bcrypt.compare(pw, this.password); };

export default mongoose.model('User', userSchema);

// ─────────────────────────────────────────────────────────────────────────────
// file: src/models/Restaurant.js
import mongoose from 'mongoose';

const restaurantSchema = new mongoose.Schema({
  name: { type: String, required: true },
  description: String,
  logoUrl: String,
  cuisines: [String],
  address: String,
  openingHours: String,
  slotCapacity: { type: Number, default: 20 }, // per slot capacity
}, { timestamps: true });

export default mongoose.model('Restaurant', restaurantSchema);

// ─────────────────────────────────────────────────────────────────────────────
// file: src/models/MenuItem.js
import mongoose from 'mongoose';

const menuItemSchema = new mongoose.Schema({
  restaurant: { type: mongoose.Schema.Types.ObjectId, ref: 'Restaurant', required: true },
  name: { type: String, required: true },
  description: String,
  priceINR: { type: Number, required: true },
  cuisine: String,
  imageUrl: String,
  available: { type: Boolean, default: true },
}, { timestamps: true });

export default mongoose.model('MenuItem', menuItemSchema);

// ─────────────────────────────────────────────────────────────────────────────
// file: src/models/DeliverySlot.js
import mongoose from 'mongoose';

const deliverySlotSchema = new mongoose.Schema({
  restaurant: { type: mongoose.Schema.Types.ObjectId, ref: 'Restaurant', required: true },
  date: { type: String, required: true }, // YYYY-MM-DD
  slot: { type: String, required: true }, // e.g. "18:00-20:00"
  capacity: { type: Number, required: true },
  booked: { type: Number, default: 0 },
}, { timestamps: true });

export default mongoose.model('DeliverySlot', deliverySlotSchema);

// ─────────────────────────────────────────────────────────────────────────────
// file: src/models/Order.js
import mongoose from 'mongoose';

const orderItemSchema = new mongoose.Schema({
  item: { type: mongoose.Schema.Types.ObjectId, ref: 'MenuItem', required: true },
  name: String,
  priceINR: Number,
  qty: Number,
});

const orderSchema = new mongoose.Schema({
  orderId: { type: String, required: true, unique: true },
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  restaurant: { type: mongoose.Schema.Types.ObjectId, ref: 'Restaurant', required: true },
  items: [orderItemSchema],
  totalINR: Number,
  status: { type: String, enum: ['Preparing', 'Out for delivery', 'Delivered', 'Cancelled'], default: 'Preparing' },
  address: String,
  phone: String,
  date: String, // YYYY-MM-DD
  slot: String, // time window
  paymentMethod: { type: String, enum: ['cod', 'card', 'upi', 'paypal', 'stripe', 'razorpay'], default: 'cod' },
  paymentRef: String,
}, { timestamps: true });

export default mongoose.model('Order', orderSchema);

// ─────────────────────────────────────────────────────────────────────────────
// file: src/services/io.js
let ioInstance = null;
export function attachIO(io){ ioInstance = io; }
export function getIO(){ return ioInstance; }

// ─────────────────────────────────────────────────────────────────────────────
// file: src/services/mailer.js
import nodemailer from 'nodemailer';

let transporter;
export function getTransporter(){
  if(transporter) return transporter;
  transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT || 587),
    secure: false,
    auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
  });
  return transporter;
}

export async function sendMail({ to, subject, html }){
  const tx = getTransporter();
  const info = await tx.sendMail({ from: process.env.FROM_EMAIL, to, subject, html });
  return info;
}

// ─────────────────────────────────────────────────────────────────────────────
// file: src/utils/id.js
export function uid(prefix = 'ORD'){
  return `${prefix}${Date.now()}${Math.floor(Math.random()*1000)}`;
}

// ─────────────────────────────────────────────────────────────────────────────
// file: src/controllers/auth.controller.js
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import User from '../models/User.js';
import { setAuthCookie } from '../middleware/auth.js';
import { sendMail } from '../services/mailer.js';

function sign(id){ return jwt.sign({ id }, process.env.JWT_SECRET, { expiresIn: '7d' }); }

export async function register(req, res, next){
  try{
    const { name, email, password, phone } = req.body;
    const exists = await User.findOne({ email });
    if(exists) return res.status(400).json({ message: 'Email already registered' });
    const user = await User.create({ name, email, password, phone });
    const token = sign(user._id);
    setAuthCookie(res, token);
    res.json({ user: { id: user._id, name: user.name, email: user.email, role: user.role } });
  }catch(e){ next(e); }
}

export async function login(req, res, next){
  try{
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if(!user || !(await user.matchPassword(password))) return res.status(400).json({ message: 'Invalid credentials' });
    const token = sign(user._id);
    setAuthCookie(res, token);
    res.json({ user: { id: user._id, name: user.name, email: user.email, role: user.role } });
  }catch(e){ next(e); }
}

export async function me(req, res){ res.json({ user: req.user }); }

export async function logout(req, res){ res.clearCookie('token'); res.json({ message: 'Logged out' }); }

export async function requestReset(req, res, next){
  try{
    const { email } = req.body;
    const user = await User.findOne({ email });
    if(!user) return res.json({ message: 'If the account exists, an email has been sent' });
    user.resetToken = crypto.randomBytes(20).toString('hex');
    user.resetTokenExp = new Date(Date.now() + 1000*60*30);
    await user.save();
    const link = `${process.env.PUBLIC_URL || ''}/reset-password?token=${user.resetToken}&email=${encodeURIComponent(user.email)}`;
    await sendMail({ to: user.email, subject: 'Reset your FoodExpress password', html: `<p>Hi ${user.name},</p><p>Reset your password by clicking <a href="${link}">here</a>. This link expires in 30 minutes.</p>` });
    res.json({ message: 'Reset email sent' });
  }catch(e){ next(e); }
}

export async function resetPassword(req, res, next){
  try{
    const { email, token, password } = req.body;
    const user = await User.findOne({ email, resetToken: token, resetTokenExp: { $gt: new Date() } });
    if(!user) return res.status(400).json({ message: 'Invalid or expired token' });
    user.password = password;
    user.resetToken = undefined; user.resetTokenExp = undefined;
    await user.save();
    res.json({ message: 'Password updated' });
  }catch(e){ next(e); }
}

// ─────────────────────────────────────────────────────────────────────────────
// file: src/controllers/restaurant.controller.js
import Restaurant from '../models/Restaurant.js';

export async function createRestaurant(req, res, next){
  try{
    const r = await Restaurant.create(req.body);
    res.status(201).json(r);
  }catch(e){ next(e); }
}
export async function listRestaurants(req, res, next){
  try{ res.json(await Restaurant.find().sort('-createdAt')); }catch(e){ next(e); }
}
export async function getRestaurant(req, res, next){
  try{
    const r = await Restaurant.findById(req.params.id);
    if(!r) return res.status(404).json({ message: 'Not found' });
    res.json(r);
  }catch(e){ next(e); }
}
export async function updateRestaurant(req, res, next){
  try{
    const r = await Restaurant.findByIdAndUpdate(req.params.id, req.body, { new: true });
    if(!r) return res.status(404).json({ message: 'Not found' });
    res.json(r);
  }catch(e){ next(e); }
}
export async function deleteRestaurant(req, res, next){
  try{ await Restaurant.findByIdAndDelete(req.params.id); res.json({ ok: true }); }catch(e){ next(e); }
}

// ─────────────────────────────────────────────────────────────────────────────
// file: src/controllers/menu.controller.js
import MenuItem from '../models/MenuItem.js';

export async function createItem(req, res, next){
  try{ const it = await MenuItem.create(req.body); res.status(201).json(it); }catch(e){ next(e); }
}
export async function listItems(req, res, next){
  try{
    const filter = {};
    if(req.query.restaurant) filter.restaurant = req.query.restaurant;
    res.json(await MenuItem.find(filter).populate('restaurant'));
  }catch(e){ next(e); }
}
export async function getItem(req, res, next){
  try{ const it = await MenuItem.findById(req.params.id); if(!it) return res.status(404).json({ message:'Not found' }); res.json(it); }catch(e){ next(e); }
}
export async function updateItem(req, res, next){
  try{ const it = await MenuItem.findByIdAndUpdate(req.params.id, req.body, { new:true }); if(!it) return res.status(404).json({ message:'Not found' }); res.json(it); }catch(e){ next(e); }
}
export async function deleteItem(req, res, next){
  try{ await MenuItem.findByIdAndDelete(req.params.id); res.json({ ok:true }); }catch(e){ next(e); }
}

// ─────────────────────────────────────────────────────────────────────────────
// file: src/controllers/slot.controller.js
import DeliverySlot from '../models/DeliverySlot.js';
import Restaurant from '../models/Restaurant.js';

export async function getSlots(req, res, next){
  try{
    const { restaurantId, date } = req.query; // YYYY-MM-DD
    const rest = await Restaurant.findById(restaurantId);
    if(!rest) return res.status(400).json({ message: 'Restaurant not found' });
    const slots = await DeliverySlot.find({ restaurant: rest._id, date });
    // if not generated yet, create default slots
    if(slots.length === 0){
      const defaults = ['09:00-11:00','12:00-14:00','18:00-20:00','20:00-22:00'];
      const created = await DeliverySlot.insertMany(defaults.map(s=>({ restaurant: rest._id, date, slot: s, capacity: rest.slotCapacity })));
      return res.json(created);
    }
    res.json(slots);
  }catch(e){ next(e); }
}

export async function bookSlot(restaurantId, date, slot){
  const found = await DeliverySlot.findOne({ restaurant: restaurantId, date, slot });
  if(!found) return null;
  if(found.booked >= found.capacity) throw new Error('Selected time slot is full');
  found.booked += 1; await found.save();
  return found;
}

// ─────────────────────────────────────────────────────────────────────────────
// file: src/controllers/order.controller.js
import Order from '../models/Order.js';
import MenuItem from '../models/MenuItem.js';
import Restaurant from '../models/Restaurant.js';
import { uid } from '../utils/id.js';
import { getIO } from '../services/io.js';
import { sendMail } from '../services/mailer.js';
import { bookSlot } from './slot.controller.js';

export async function placeOrder(req, res, next){
  try{
    const { restaurantId, items, address, phone, date, slot, paymentMethod, paymentRef } = req.body;
    const rest = await Restaurant.findById(restaurantId);
    if(!rest) return res.status(400).json({ message: 'Restaurant not found' });

    // Load items & compute total
    const ids = items.map(i=>i.itemId);
    const dbItems = await MenuItem.find({ _id: { $in: ids }, available: true });
    const map = Object.fromEntries(dbItems.map(i=>[String(i._id), i]));
    const orderItems = items.map(i=>({
      item: i.itemId,
      name: map[i.itemId]?.name || 'Item',
      priceINR: map[i.itemId]?.priceINR || 0,
      qty: i.qty,
    }));
    const totalINR = orderItems.reduce((s,i)=>s + (i.priceINR * i.qty), 0);

    // Book delivery slot
    await bookSlot(rest._id, date, slot);

    const orderId = uid('ORD');
    const order = await Order.create({
      orderId,
      user: req.user?._id,
      restaurant: rest._id,
      items: orderItems,
      totalINR,
      status: 'Preparing',
      address, phone, date, slot,
      paymentMethod: paymentMethod || 'cod',
      paymentRef
    });

    // Notify via email
    if(req.user?.email){
      await sendMail({
        to: req.user.email,
        subject: `Order confirmed: ${order.orderId}`,
        html: `<p>Thanks for your order!</p><p>Order ID: <b>${order.orderId}</b></p><p>Total: ₹${totalINR}</p><p>Status: Preparing</p>`
      });
    }

    // Socket room broadcast
    const io = getIO();
    io.to(`order:${order.orderId}`).emit('order:update', { orderId: order.orderId, status: order.status });

    res.status(201).json(order);
  }catch(e){ next(e); }
}

export async function getOrder(req, res, next){
  try{
    const order = await Order.findOne({ orderId: req.params.orderId }).populate('items.item');
    if(!order) return res.status(404).json({ message: 'Not found' });
    res.json(order);
  }catch(e){ next(e); }
}

export async function myOrders(req, res, next){
  try{ res.json(await Order.find({ user: req.user._id }).sort('-createdAt')); }catch(e){ next(e); }
}

export async function updateStatus(req, res, next){
  try{
    const order = await Order.findOne({ orderId: req.params.orderId });
    if(!order) return res.status(404).json({ message: 'Not found' });
    order.status = req.body.status;
    await order.save();

    // Notify user via email (optional)
    const html = `<p>Your order <b>${order.orderId}</b> status changed to <b>${order.status}</b>.</p>`;
    // In a real app, look up user's email via population
    await sendMail({ to: req.body.email || 'test@example.com', subject: `Order ${order.orderId} update`, html }).catch(()=>{});

    const io = getIO();
    io.to(`order:${order.orderId}`).emit('order:update', { orderId: order.orderId, status: order.status });

    res.json(order);
  }catch(e){ next(e); }
}

// ─────────────────────────────────────────────────────────────────────────────
// file: src/controllers/upload.controller.js
export async function uploadFile(req, res){
  const file = req.file;
  res.json({
    filename: file.filename,
    path: `/uploads/${file.filename}`,
    mimetype: file.mimetype,
    size: file.size
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// file: src/controllers/analytics.controller.js
import Order from '../models/Order.js';
import MenuItem from '../models/MenuItem.js';

export async function getAnalytics(req, res, next){
  try{
    const totalOrders = await Order.countDocuments();
    const revenueAgg = await Order.aggregate([{ $group: { _id: null, total: { $sum: '$totalINR' } } }]);
    const revenue = revenueAgg[0]?.total || 0;
    const topItems = await Order.aggregate([
      { $unwind: '$items' },
      { $group: { _id: '$items.name', qty: { $sum: '$items.qty' }, revenue: { $sum: { $multiply: ['$items.priceINR', '$items.qty'] } } } },
      { $sort: { qty: -1 } },
      { $limit: 5 }
    ]);
    res.json({ totalOrders, revenue, topItems });
  }catch(e){ next(e); }
}

// ─────────────────────────────────────────────────────────────────────────────
// file: src/controllers/payment.controller.js
import Stripe from 'stripe';
import Razorpay from 'razorpay';

const stripe = process.env.STRIPE_SECRET ? new Stripe(process.env.STRIPE_SECRET) : null;
const razorpay = (process.env.RAZORPAY_KEY_ID && process.env.RAZORPAY_KEY_SECRET) ? new Razorpay({ key_id: process.env.RAZORPAY_KEY_ID, key_secret: process.env.RAZORPAY_KEY_SECRET }) : null;

export async function createStripeIntent(req, res, next){
  try{
    if(!stripe) return res.status(400).json({ message: 'Stripe not configured' });
    const { amountINR } = req.body;
    const paymentIntent = await stripe.paymentIntents.create({
      amount: Math.round(Number(amountINR) * 100),
      currency: 'inr',
      automatic_payment_methods: { enabled: true },
      description: 'FoodExpress order',
    });
    res.json({ clientSecret: paymentIntent.client_secret });
  }catch(e){ next(e); }
}

export async function createRazorpayOrder(req, res, next){
  try{
    if(!razorpay) return res.status(400).json({ message: 'Razorpay not configured' });
    const { amountINR, receipt } = req.body;
    const order = await razorpay.orders.create({ amount: Math.round(Number(amountINR) * 100), currency: 'INR', receipt: receipt || `rcpt_${Date.now()}` });
    res.json(order);
  }catch(e){ next(e); }
}

// ─────────────────────────────────────────────────────────────────────────────
// file: src/routes/auth.routes.js
import { Router } from 'express';
import { register, login, me, logout, requestReset, resetPassword } from '../controllers/auth.controller.js';
import { protect } from '../middleware/auth.js';

const r = Router();

r.post('/register', register);
r.post('/login', login);
r.get('/me', protect(), me);
r.post('/logout', logout);

r.post('/request-reset', requestReset);
r.post('/reset-password', resetPassword);

export default r;

// ─────────────────────────────────────────────────────────────────────────────
// file: src/routes/restaurant.routes.js
import { Router } from 'express';
import { createRestaurant, listRestaurants, getRestaurant, updateRestaurant, deleteRestaurant } from '../controllers/restaurant.controller.js';
import { protect } from '../middleware/auth.js';

const r = Router();

r.get('/', listRestaurants);
r.get('/:id', getRestaurant);

// Admin only
r.post('/', protect(['admin']), createRestaurant);
r.put('/:id', protect(['admin']), updateRestaurant);
r.delete('/:id', protect(['admin']), deleteRestaurant);

export default r;

// ─────────────────────────────────────────────────────────────────────────────
// file: src/routes/menu.routes.js
import { Router } from 'express';
import { createItem, listItems, getItem, updateItem, deleteItem } from '../controllers/menu.controller.js';
import { protect } from '../middleware/auth.js';

const r = Router();

r.get('/', listItems);
r.get('/:id', getItem);

r.post('/', protect(['admin']), createItem);
r.put('/:id', protect(['admin']), updateItem);
r.delete('/:id', protect(['admin']), deleteItem);

export default r;

// ─────────────────────────────────────────────────────────────────────────────
// file: src/routes/order.routes.js
import { Router } from 'express';
import { placeOrder, getOrder, updateStatus, myOrders } from '../controllers/order.controller.js';
import { getSlots } from '../controllers/slot.controller.js';
import { protect } from '../middleware/auth.js';

const r = Router();

// Delivery time slots
r.get('/slots', getSlots);

// Orders
r.post('/', protect(), placeOrder);
r.get('/mine', protect(), myOrders);
r.get('/:orderId', protect(), getOrder);

// Admin: update status
r.put('/:orderId/status', protect(['admin']), updateStatus);

export default r;

// ─────────────────────────────────────────────────────────────────────────────
// file: src/routes/upload.routes.js
import { Router } from 'express';
import multer from 'multer';
import path from 'path';
import { uploadFile } from '../controllers/upload.controller.js';
import { protect } from '../middleware/auth.js';
import mime from 'mime-types';

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads/'),
  filename: (req, file, cb) => {
    const ext = mime.extension(file.mimetype) || path.extname(file.originalname);
    cb(null, `${Date.now()}_${Math.random().toString(36).slice(2)}.${ext}`);
  }
});

const upload = multer({ storage });

const r = Router();

// Admin can upload images/logos
r.post('/', protect(['admin']), upload.single('file'), uploadFile);

export default r;

// ─────────────────────────────────────────────────────────────────────────────
// file: src/routes/analytics.routes.js
import { Router } from 'express';
import { getAnalytics } from '../controllers/analytics.controller.js';
import { protect } from '../middleware/auth.js';

const r = Router();

r.get('/', protect(['admin']), getAnalytics);

export default r;

// ─────────────────────────────────────────────────────────────────────────────
// file: src/routes/payment.routes.js
import { Router } from 'express';
import { createStripeIntent, createRazorpayOrder } from '../controllers/payment.controller.js';
import { protect } from '../middleware/auth.js';

const r = Router();

r.post('/stripe/intent', protect(), createStripeIntent);
r.post('/razorpay/order', protect(), createRazorpayOrder);

export default r;

// ─────────────────────────────────────────────────────────────────────────────
// file: src/frontend/state/cartSlice.js (Optional — Redux Toolkit for your frontend)
// This is a tiny example you can paste into your React app to manage cart state.
// Install in frontend: npm i @reduxjs/toolkit react-redux
import { createSlice } from '@reduxjs/toolkit';

const initialState = { items: [] }; // {itemId, qty}

const slice = createSlice({
  name: 'cart',
  initialState,
  reducers: {
    addToCart(state, action){
      const { itemId, qty = 1 } = action.payload;
      const found = state.items.find(i=>i.itemId===itemId);
      if(found) found.qty += qty; else state.items.push({ itemId, qty });
    },
    changeQty(state, action){
      const { itemId, delta } = action.payload;
      const it = state.items.find(i=>i.itemId===itemId);
      if(!it) return; it.qty += delta; if(it.qty<=0) state.items = state.items.filter(i=>i.itemId!==itemId);
    },
    clearCart(state){ state.items = []; }
  }
});

export const { addToCart, changeQty, clearCart } = slice.actions;
export default slice.reducer;

// Example checkout thunk (call backend /api/orders)
export function placeOrderThunk(payload){
  return async (dispatch, getState) => {
    const res = await fetch('/api/orders', { method:'POST', headers:{ 'Content-Type':'application/json' }, credentials:'include', body: JSON.stringify(payload) });
    if(!res.ok) throw new Error('Order failed');
    const data = await res.json();
    dispatch(clearCart());
    return data;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// file: src/frontend/state/store.js (Optional)
import { configureStore } from '@reduxjs/toolkit';
import cartReducer from './cartSlice.js';

export default configureStore({ reducer: { cart: cartReducer } });

// ─────────────────────────────────────────────────────────────────────────────
// QUICK TEST NOTES
// Use Postman or curl:
// 1) Register: POST /api/auth/register { name,email,password }
// 2) Login: POST /api/auth/login { email,password }
// 3) Create restaurant (admin required): make your user admin manually in DB or add a seeder.
// 4) Create menu item: POST /api/menu { restaurant, name, priceINR, cuisine }
// 5) Get slots: GET /api/orders/slots?restaurantId=...&date=2025-08-20
// 6) Place order: POST /api/orders { restaurantId, items:[{itemId,qty}], address, phone, date, slot, paymentMethod }
// 7) Track: GET /api/orders/:orderId
// 8) Admin status update: PUT /api/orders/:orderId/status { status: 'Out for delivery' }
// Socket.io: client should join `order:<ORDER_ID>` and listen for `order:update` event.

