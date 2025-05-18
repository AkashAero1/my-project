const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const path = require('path');
require('dotenv').config();

const User = require('./models/User');
const Message = require('./models/Message');

const app = express();
const server = http.createServer(app);

// Production configuration
const isProduction = process.env.NODE_ENV === 'production';
const CLIENT_URL = isProduction ? process.env.CLIENT_URL : 'http://localhost:3000';
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/studentwell';
const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret';
const SESSION_SECRET = process.env.SESSION_SECRET || 'your_session_secret';

// Socket.io configuration with CORS
const io = socketIo(server, {
  cors: { 
    origin: CLIENT_URL,
    methods: ["GET", "POST"],
    credentials: true
  }
});

// MongoDB connection with retry logic and connection test
const connectDB = async () => {
  try {
    await mongoose.connect(MONGODB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    console.log('MongoDB connected successfully');
    
    // Test the connection by creating a test user
    try {
      const testUser = await User.findOne({ email: 'test@test.com' });
      if (!testUser) {
        const hash = await bcrypt.hash('test123', 10);
        await User.create({
          username: 'TestUser',
          email: 'test@test.com',
          password: hash
        });
        console.log('Test user created successfully');
      }
    } catch (err) {
      console.log('Test user already exists or error:', err.message);
    }
  } catch (err) {
    console.error('MongoDB connection error:', err);
    // Retry connection after 5 seconds
    setTimeout(connectDB, 5000);
  }
};

connectDB();

// Middleware
app.use(cors({ 
  origin: CLIENT_URL,
  credentials: true 
}));
app.use(express.json());
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({ 
    mongoUrl: MONGODB_URI,
    ttl: 24 * 60 * 60 // 1 day
  }),
  cookie: { 
    secure: isProduction,
    httpOnly: true,
    sameSite: isProduction ? 'none' : 'lax',
    maxAge: 24 * 60 * 60 * 1000 // 1 day
  }
}));

// Serve static files in production
if (isProduction) {
  app.use(express.static(path.join(__dirname, 'website')));
  
  // Serve index.html for all routes in production
  app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'website', 'index.html'));
  });
}

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

// Track online users
const onlineUsers = new Map();

// Socket.io for chat
io.use(async (socket, next) => {
  const token = socket.handshake.auth?.token;
  if (!token) return next(new Error('No token'));
  try {
    const user = jwt.verify(token, JWT_SECRET);
    socket.user = user;
    next();
  } catch (err) {
    next(new Error('Invalid token'));
  }
});

io.on('connection', (socket) => {
  // Add user to online users
  onlineUsers.set(socket.user.id, {
    username: socket.user.username,
    avatar: socket.user.avatar,
    lastSeen: new Date()
  });
  
  // Broadcast user online status
  io.emit('user status', {
    userId: socket.user.id,
    username: socket.user.username,
    status: 'online'
  });

  // Typing indicator with debounce
  let typingTimeout;
  socket.on('typing', (isTyping) => {
    clearTimeout(typingTimeout);
    socket.broadcast.emit('typing', { 
      userId: socket.user.id,
      username: socket.user.username, 
      isTyping 
    });
    if (isTyping) {
      typingTimeout = setTimeout(() => {
        socket.broadcast.emit('typing', { 
          userId: socket.user.id,
          username: socket.user.username, 
          isTyping: false 
        });
      }, 3000);
    }
  });

  // Chat message with error handling and read receipts
  socket.on('chat message', async (msg) => {
    try {
      const message = await Message.create({
        user: socket.user.id,
        username: socket.user.username,
        avatar: socket.user.avatar,
        text: msg,
        readBy: [socket.user.id] // Mark as read by sender
      });

      const messageData = {
        id: message._id,
        username: message.username,
        avatar: message.avatar,
        text: message.text,
        createdAt: message.createdAt,
        readBy: message.readBy
      };

      io.emit('chat message', messageData);
    } catch (err) {
      socket.emit('error', { message: 'Failed to send message' });
    }
  });

  // Message read receipt
  socket.on('message read', async (messageId) => {
    try {
      await Message.findByIdAndUpdate(messageId, {
        $addToSet: { readBy: socket.user.id }
      });
      io.emit('message read update', {
        messageId,
        readBy: socket.user.id,
        username: socket.user.username
      });
    } catch (err) {
      socket.emit('error', { message: 'Failed to update read status' });
    }
  });

  // Handle disconnection
  socket.on('disconnect', () => {
    onlineUsers.set(socket.user.id, {
      ...onlineUsers.get(socket.user.id),
      lastSeen: new Date(),
      status: 'offline'
    });
    
    io.emit('user status', {
      userId: socket.user.id,
      username: socket.user.username,
      status: 'offline',
      lastSeen: new Date()
    });
  });
});

// Get chat history with pagination
app.get('/api/messages', auth, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 50;
    const skip = (page - 1) * limit;

    const messages = await Message.find()
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .lean();

    const total = await Message.countDocuments();

    res.json({
      messages: messages.reverse(),
      pagination: {
        currentPage: page,
        totalPages: Math.ceil(total / limit),
        totalMessages: total
      }
    });
  } catch (err) {
    res.status(500).json({ message: 'Failed to fetch messages' });
  }
});

// Get online users
app.get('/api/online-users', auth, (req, res) => {
  const users = Array.from(onlineUsers.entries()).map(([id, data]) => ({
    userId: id,
    ...data
  }));
  res.json(users);
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ 
    message: isProduction ? 'Internal server error' : err.message 
  });
});

const PORT = process.env.PORT || 3001;
server.listen(PORT, () => {
  console.log(`Server running in ${isProduction ? 'production' : 'development'} mode on port ${PORT}`);
});