const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const User = require('./models/User');
const Message = require('./models/Message');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: { origin: "*", methods: ["GET", "POST"] }
});

const JWT_SECRET = 'your_jwt_secret'; // Change this in production

// MongoDB connection
mongoose.connect('mongodb://localhost:27017/studentwell', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// Middleware
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(session({
  secret: 'your_session_secret',
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({ mongoUrl: 'mongodb://localhost:27017/studentwell' }),
  cookie: { secure: false, httpOnly: true }
}));

// Auth Middleware
function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'No token' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    res.status(401).json({ message: 'Invalid token' });
  }
}

// Register
app.post('/api/register', async (req, res) => {
  const { username, email, password, avatar } = req.body;
  if (!username || !email || !password) return res.status(400).json({ message: 'Missing fields' });
  const hash = await bcrypt.hash(password, 10);
  try {
    const user = await User.create({ username, email, password: hash, avatar });
    res.json({ message: 'Registered' });
  } catch (e) {
    res.status(400).json({ message: 'User exists' });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.status(400).json({ message: 'No user' });
  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(400).json({ message: 'Wrong password' });
  const token = jwt.sign({ id: user._id, username: user.username, avatar: user.avatar }, JWT_SECRET, { expiresIn: '1d' });
  res.json({ token, username: user.username, avatar: user.avatar });
});

// Get chat history
app.get('/api/messages', auth, async (req, res) => {
  const messages = await Message.find().sort({ createdAt: 1 }).limit(100);
  res.json(messages);
});

// Socket.io for chat
io.use(async (socket, next) => {
  const token = socket.handshake.auth?.token;
  if (!token) return next(new Error('No token'));
  try {
    const user = jwt.verify(token, JWT_SECRET);
    socket.user = user;
    next();
  } catch {
    next(new Error('Invalid token'));
  }
});

io.on('connection', (socket) => {
  // Typing indicator
  socket.on('typing', (isTyping) => {
    socket.broadcast.emit('typing', { username: socket.user.username, isTyping });
  });

  // Chat message
  socket.on('chat message', async (msg) => {
    const message = await Message.create({
      user: socket.user.id,
      username: socket.user.username,
      avatar: socket.user.avatar,
      text: msg
    });
    io.emit('chat message', {
      username: message.username,
      avatar: message.avatar,
      text: message.text,
      createdAt: message.createdAt
    });
  });
});

const PORT = process.env.PORT || 3001;
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});