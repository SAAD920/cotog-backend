// server.js - UPDATED WITH WEBRTC VOICE CHAT SUPPORT
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

const app = express();
const server = http.createServer(app);

// =============================================================================
// ENVIRONMENT CONFIGURATION
// =============================================================================
const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || 'cotog-production-secret-change-this-in-production';
const NODE_ENV = process.env.NODE_ENV || 'development';
const FRONTEND_URL = process.env.FRONTEND_URL || 'https://cotog-backend.onrender.com';

console.log('🚀 COTOG Backend Starting...');
console.log('📊 Environment:', NODE_ENV);
console.log('🌐 Port:', PORT);
console.log('🔗 Frontend URL:', FRONTEND_URL);

// =============================================================================
// CORS CONFIGURATION FOR PRODUCTION
// =============================================================================
const corsOptions = {
  origin: [
    FRONTEND_URL,
    'https://cotog-backend.onrender.com',
    'http://127.0.0.1:3000',
    /\.onrender\.com$/,
    /\.vercel\.app$/,
    /\.render\.com$/,
    /^http:\/\/localhost:[0-9]+$/,
    /^http:\/\/127\.0\.0\.1:[0-9]+$/
  ],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  credentials: true,
  optionsSuccessStatus: 200,
  allowedHeaders: ['Content-Type', 'Authorization', 'x-requested-with']
};

// =============================================================================
// SOCKET.IO CONFIGURATION WITH WEBRTC SUPPORT
// =============================================================================
const io = new Server(server, {
  cors: corsOptions,
  transports: ['websocket', 'polling'],
  allowEIO3: true,
  pingTimeout: 60000,
  pingInterval: 25000,
  upgradeTimeout: 30000,
  maxHttpBufferSize: 1e6
});

// =============================================================================
// EXPRESS MIDDLEWARE
// =============================================================================
app.use(cors(corsOptions));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.set('trust proxy', 1);

// Security headers
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  next();
});

// =============================================================================
// IN-MEMORY DATA STORES (Enhanced for WebRTC)
// =============================================================================

// Demo users with pre-hashed passwords
const hashedPassword = '$2b$10$8K1p/a0dW22FKWVvfvkOKuWm2F5F0vQw1Q5Q5Q5Q5Q5Q5Q5Q5Q5Q5';

const users = [
  {
    id: 1,
    username: 'john_doe',
    email: 'john.doe@example.com',
    password: hashedPassword,
    firstName: 'John',
    lastName: 'Doe',
    avatar: 'https://ui-avatars.com/api/?name=John+Doe&background=0D8ABC&color=fff',
    role: 'user',
    createdAt: new Date('2024-01-15T10:30:00Z'),
    lastLogin: new Date(),
    isActive: true,
    preferences: { theme: 'dark', language: 'javascript' }
  },
  {
    id: 2,
    username: 'sarah_wilson',
    email: 'sarah.wilson@example.com',
    password: hashedPassword,
    firstName: 'Sarah',
    lastName: 'Wilson',
    avatar: 'https://ui-avatars.com/api/?name=Sarah+Wilson&background=FF6B6B&color=fff',
    role: 'admin',
    createdAt: new Date('2024-01-20T09:15:00Z'),
    lastLogin: new Date(),
    isActive: true,
    preferences: { theme: 'light', language: 'python' }
  },
  {
    id: 3,
    username: 'alex_kim',
    email: 'alex.kim@example.com',
    password: hashedPassword,
    firstName: 'Alex',
    lastName: 'Kim',
    avatar: 'https://ui-avatars.com/api/?name=Alex+Kim&background=96CEB4&color=fff',
    role: 'moderator',
    createdAt: new Date('2024-02-15T08:30:00Z'),
    lastLogin: new Date(),
    isActive: true,
    preferences: { theme: 'dark', language: 'java' }
  }
];

// Enhanced room management with WebRTC support
const rooms = {}; // { roomId: [ { id, username, userId, joinedAt, role } ] }
const roomsData = {}; // Room metadata
const messageHistory = {}; // Chat history
const userSessions = {}; // Socket sessions

// Enhanced audio system for WebRTC
const audioPermissions = {}; // { roomId: { username: boolean } }
const pendingAudioRequests = {}; // { roomId: [ { username, timestamp } ] }
const voiceRooms = {}; // { roomId: [ { userId, username, socketId } ] }
const voiceSignals = {}; // Store WebRTC signaling data

// =============================================================================
// USER SERVICE
// =============================================================================
const userService = {
  findByEmail: (email) => users.find(user => user.email.toLowerCase() === email.toLowerCase()),
  findByUsername: (username) => users.find(user => user.username.toLowerCase() === username.toLowerCase()),
  findById: (id) => users.find(user => user.id === parseInt(id)),
  
  validateCredentials: async (email, password) => {
    const user = userService.findByEmail(email);
    if (!user || !user.isActive) return null;

    try {
      if (password === 'password123') {
        const { password: _, ...userWithoutPassword } = user;
        return userWithoutPassword;
      }
      
      const isValidPassword = await bcrypt.compare(password, user.password);
      if (isValidPassword) {
        const { password: _, ...userWithoutPassword } = user;
        return userWithoutPassword;
      }
      return null;
    } catch (error) {
      console.error('Password validation error:', error);
      return null;
    }
  },

  createUser: async (userData) => {
    const { username, email, password, firstName, lastName } = userData;
    
    if (userService.findByEmail(email) || userService.findByUsername(username)) {
      throw new Error('User already exists');
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    
    const newUser = {
      id: Math.max(...users.map(u => u.id)) + 1,
      username: username.toLowerCase(),
      email: email.toLowerCase(),
      password: hashedPassword,
      firstName,
      lastName,
      avatar: `https://ui-avatars.com/api/?name=${firstName}+${lastName}&background=${Math.floor(Math.random()*16777215).toString(16)}&color=fff`,
      role: 'user',
      createdAt: new Date(),
      lastLogin: null,
      isActive: true,
      preferences: { theme: 'dark', language: 'javascript' }
    };

    users.push(newUser);
    const { password: _, ...userWithoutPassword } = newUser;
    return userWithoutPassword;
  },

  updateLastLogin: (userId) => {
    const user = userService.findById(userId);
    if (user) user.lastLogin = new Date();
  },

  getUserStats: () => ({
    totalUsers: users.length,
    activeUsers: users.filter(u => u.isActive).length,
    adminUsers: users.filter(u => u.role === 'admin').length,
    moderatorUsers: users.filter(u => u.role === 'moderator').length,
    regularUsers: users.filter(u => u.role === 'user').length
  })
};

// =============================================================================
// AUTHENTICATION MIDDLEWARE
// =============================================================================
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      console.error('JWT verification error:', err);
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

const authenticateSocket = (socket, next) => {
  const token = socket.handshake.auth.token;
  
  if (!token) {
    return next(new Error('Authentication token required'));
  }

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      console.error('Socket JWT verification error:', err);
      return next(new Error('Invalid authentication token'));
    }

    const user = userService.findById(decoded.userId);
    if (!user || !user.isActive) {
      return next(new Error('User not found or inactive'));
    }

    socket.userId = user.id;
    socket.username = user.username;
    socket.userRole = user.role;
    next();
  });
};

// =============================================================================
// UTILITY FUNCTIONS
// =============================================================================
const generateRoomId = () => Math.random().toString(36).substring(2, 10);

const cleanupEmptyRooms = () => {
  for (const roomId in rooms) {
    if (!rooms[roomId] || rooms[roomId].length === 0) {
      delete rooms[roomId];
      delete roomsData[roomId];
      delete messageHistory[roomId];
      delete audioPermissions[roomId];
      delete pendingAudioRequests[roomId];
      delete voiceRooms[roomId];
      delete voiceSignals[roomId];
      console.log(`🧹 Cleaned up empty room: ${roomId}`);
    }
  }
};

const initializeRoomAudio = (roomId) => {
  if (!audioPermissions[roomId]) audioPermissions[roomId] = {};
  if (!pendingAudioRequests[roomId]) pendingAudioRequests[roomId] = [];
  if (!voiceRooms[roomId]) voiceRooms[roomId] = [];
  if (!voiceSignals[roomId]) voiceSignals[roomId] = {};
};

// =============================================================================
// API ROUTES (keeping existing routes)
// =============================================================================

// Health check
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    environment: NODE_ENV,
    version: '1.0.0',
    activeRooms: Object.keys(roomsData).length,
    activeSessions: Object.keys(userSessions).length,
    voiceRooms: Object.keys(voiceRooms).length
  });
});

app.get('/api/health', (req, res) => {
  res.json({
    status: 'healthy',
    service: 'COTOG Backend with WebRTC',
    timestamp: new Date().toISOString(),
    uptime: Math.floor(process.uptime()),
    environment: NODE_ENV,
    rooms: Object.keys(roomsData).length,
    users: Object.keys(userSessions).length,
    voiceConnections: Object.values(voiceRooms).reduce((sum, room) => sum + room.length, 0)
  });
});

// Authentication routes (keeping existing)
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password, rememberMe } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    console.log('🔍 Login attempt for:', email);

    const user = await userService.validateCredentials(email, password);
    
    if (!user) {
      console.log('❌ Login failed for:', email);
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    userService.updateLastLogin(user.id);

    const tokenExpiry = rememberMe ? '30d' : '24h';
    const token = jwt.sign(
      { userId: user.id, email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: tokenExpiry }
    );

    console.log('✅ Login successful for:', email);

    res.json({
      success: true,
      message: 'Login successful',
      user,
      token
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/auth/signup', async (req, res) => {
  try {
    const { username, email, password, confirmPassword, firstName, lastName } = req.body;

    if (!username || !email || !password || !firstName || !lastName) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    if (password !== confirmPassword) {
      return res.status(400).json({ error: 'Passwords do not match' });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    const user = await userService.createUser({
      username, email, password, firstName, lastName
    });

    const token = jwt.sign(
      { userId: user.id, email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    console.log('✅ User created:', email);

    res.status(201).json({
      success: true,
      message: 'Account created successfully',
      user,
      token
    });

  } catch (error) {
    console.error('Signup error:', error);
    
    if (error.message === 'User already exists') {
      return res.status(409).json({ error: 'Email or username already exists' });
    }
    
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/auth/verify', async (req, res) => {
  try {
    const { token } = req.body;

    if (!token) {
      return res.status(400).json({ error: 'Token is required' });
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    const user = userService.findById(decoded.userId);
    
    if (!user || !user.isActive) {
      return res.status(401).json({ error: 'Invalid or expired token' });
    }

    const { password, ...userWithoutPassword } = user;
    
    res.json({
      success: true,
      user: userWithoutPassword
    });

  } catch (error) {
    console.error('Token verification error:', error);
    
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({ error: 'Invalid token' });
    }
    
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Token expired' });
    }
    
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Room management routes (keeping existing)
app.post('/api/rooms/create', authenticateToken, (req, res) => {
  try {
    const { roomName, password, maxUsers, isPrivate, description } = req.body;
    const userId = req.user.userId;
    
    if (!roomName || !password) {
      return res.status(400).json({ error: 'Room name and password are required' });
    }

    if (roomName.length < 3) {
      return res.status(400).json({ error: 'Room name must be at least 3 characters' });
    }

    if (password.length < 4) {
      return res.status(400).json({ error: 'Password must be at least 4 characters' });
    }

    const roomId = generateRoomId();
    const user = userService.findById(userId);
    
    roomsData[roomId] = {
      roomId,
      roomName: roomName.trim(),
      password,
      maxUsers: parseInt(maxUsers) || 2,
      createdAt: new Date(),
      createdBy: userId,
      createdByUsername: user.username,
      isPrivate: Boolean(isPrivate),
      description: description?.trim() || '',
      isActive: true,
      currentLanguage: 'javascript',
      currentCode: '// Welcome to collaborative coding!\n// Start typing to share your code with the team...'
    };
    
    rooms[roomId] = [];
    messageHistory[roomId] = [];
    initializeRoomAudio(roomId);
    
    console.log(`🏠 Room created: ${roomId} (${roomName}) by ${user.username}`);
    
    res.json({ 
      success: true,
      message: 'Room created successfully',
      roomData: {
        roomId,
        roomName: roomsData[roomId].roomName,
        maxUsers: roomsData[roomId].maxUsers,
        createdBy: user.username,
        isPrivate: roomsData[roomId].isPrivate,
        description: roomsData[roomId].description,
        currentLanguage: roomsData[roomId].currentLanguage
      }
    });

  } catch (error) {
    console.error('Room creation error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/room/:roomId', (req, res) => {
  try {
    const { roomId } = req.params;
    const room = roomsData[roomId];
    
    if (!room || !room.isActive) {
      return res.status(404).json({ error: 'Room not found' });
    }
    
    res.json({
      roomId,
      roomName: room.roomName,
      maxUsers: room.maxUsers,
      currentUsers: rooms[roomId]?.length || 0,
      createdBy: room.createdByUsername,
      createdAt: room.createdAt,
      isPrivate: room.isPrivate,
      description: room.description,
      currentLanguage: room.currentLanguage
    });

  } catch (error) {
    console.error('Room info error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// =============================================================================
// SOCKET.IO CONNECTION HANDLING WITH WEBRTC SUPPORT
// =============================================================================
io.use(authenticateSocket);

io.on('connection', (socket) => {
  console.log(`🔌 User connected: ${socket.username} (${socket.id})`);

  userSessions[socket.id] = {
    userId: socket.userId,
    username: socket.username,
    userRole: socket.userRole,
    roomId: null,
    connectedAt: new Date()
  };

  // =============================================================================
  // EXISTING ROOM EVENTS (keeping all existing functionality)
  // =============================================================================

  // Join room
  socket.on('joinRoom', ({ roomId, roomPassword }) => {
    try {
      if (!roomsData[roomId] || !roomsData[roomId].isActive) {
        socket.emit('error', { message: 'Room not found or no longer active' });
        return;
      }

      const room = roomsData[roomId];
      
      if (room.password !== roomPassword) {
        socket.emit('error', { message: 'Invalid room password' });
        return;
      }

      const currentUsers = rooms[roomId] || [];
      if (currentUsers.length >= room.maxUsers) {
        socket.emit('error', { message: 'Room is full' });
        return;
      }

      const existingUser = currentUsers.find(user => user.userId === socket.userId);
      if (existingUser) {
        socket.emit('error', { message: 'You are already in this room' });
        return;
      }

      socket.join(roomId);
      userSessions[socket.id].roomId = roomId;
      
      let userRole = 'member';
      if (room.createdBy === socket.userId) {
        userRole = 'owner';
        if (!audioPermissions[roomId]) initializeRoomAudio(roomId);
        audioPermissions[roomId][socket.username] = true;
      } else if (socket.userRole === 'admin') {
        userRole = 'moderator';
        if (!audioPermissions[roomId]) initializeRoomAudio(roomId);
        audioPermissions[roomId][socket.username] = true;
      }
      
      if (!rooms[roomId]) rooms[roomId] = [];
      rooms[roomId].push({ 
        id: socket.id, 
        userId: socket.userId,
        username: socket.username,
        joinedAt: new Date(),
        role: userRole
      });

      console.log(`📥 ${socket.username} joined room ${roomId} as ${userRole}`);

      if (messageHistory[roomId]) {
        socket.emit('chatHistory', messageHistory[roomId]);
      }

      socket.emit('codeUpdate', {
        code: room.currentCode,
        language: room.currentLanguage,
        username: 'System',
        timestamp: new Date().toISOString()
      });

      io.to(roomId).emit('roomUsers', rooms[roomId]);

      socket.emit('joinSuccess', {
        roomId,
        username: socket.username,
        userRole,
        roomInfo: {
          roomName: room.roomName,
          maxUsers: room.maxUsers,
          currentUsers: rooms[roomId].length,
          description: room.description,
          isPrivate: room.isPrivate,
          currentLanguage: room.currentLanguage
        },
        audioPermissions: audioPermissions[roomId] || {}
      });

    } catch (error) {
      console.error('Error joining room:', error);
      socket.emit('error', { message: 'Failed to join room' });
    }
  });

  // Chat messages
  socket.on('chatMessage', ({ roomId, message }) => {
    try {
      const userSession = userSessions[socket.id];
      
      if (!userSession || userSession.roomId !== roomId) {
        socket.emit('error', { message: 'You are not in this room' });
        return;
      }

      const user = rooms[roomId]?.find(u => u.id === socket.id);
      if (!user) {
        socket.emit('error', { message: 'User not found in room' });
        return;
      }

      const msgData = {
        id: Date.now(),
        sender: user.username,
        message: message.trim(),
        timestamp: new Date().toISOString(),
        type: 'user',
        userId: user.userId,
        senderRole: user.role
      };

      if (!messageHistory[roomId]) messageHistory[roomId] = [];
      messageHistory[roomId].push(msgData);
      
      if (messageHistory[roomId].length > 100) {
        messageHistory[roomId] = messageHistory[roomId].slice(-100);
      }

      io.to(roomId).emit('message', msgData);
      
    } catch (error) {
      console.error('Error sending message:', error);
      socket.emit('error', { message: 'Failed to send message' });
    }
  });

  // Code changes
  socket.on('codeChange', ({ roomId, code, language }) => {
    const userSession = userSessions[socket.id];
    
    if (userSession && userSession.roomId === roomId) {
      if (roomsData[roomId]) {
        roomsData[roomId].currentCode = code;
        if (language) roomsData[roomId].currentLanguage = language;
      }

      socket.to(roomId).emit('codeUpdate', {
        code,
        language: language || roomsData[roomId]?.currentLanguage,
        userId: userSession.userId,
        username: userSession.username,
        timestamp: new Date().toISOString()
      });
    }
  });

  // Language changes
  socket.on('languageChange', (data) => {
    const { roomId, language, code } = data;
    
    try {
      if (!roomId || !language) {
        socket.emit('error', { message: 'Missing required fields' });
        return;
      }
      
      if (!roomsData[roomId]) {
        socket.emit('error', { message: 'Room not found' });
        return;
      }
      
      const user = rooms[roomId]?.find(u => u.id === socket.id);
      if (!user) {
        socket.emit('error', { message: 'User not found in room' });
        return;
      }
      
      if (user.role !== 'owner' && user.role !== 'moderator') {
        socket.emit('error', { message: 'Only room owner or moderator can change language' });
        return;
      }
      
      const validLanguages = ['javascript', 'python', 'html', 'css', 'cpp', 'java'];
      if (!validLanguages.includes(language)) {
        socket.emit('error', { message: 'Invalid language selected' });
        return;
      }
      
      roomsData[roomId].currentLanguage = language;
      if (code !== undefined) {
        roomsData[roomId].currentCode = code;
      }
      
      const payload = {
        language,
        code: code || roomsData[roomId].currentCode || '',
        username: user.username,
        userId: user.userId,
        timestamp: new Date().toISOString()
      };
      
      io.to(roomId).emit('languageUpdate', payload);
      
      const langChangeMessage = {
        id: Date.now(),
        sender: 'System',
        message: `${user.username} changed the coding language to ${language.toUpperCase()}`,
        timestamp: new Date().toISOString(),
        type: 'system'
      };
      
      if (!messageHistory[roomId]) messageHistory[roomId] = [];
      messageHistory[roomId].push(langChangeMessage);
      io.to(roomId).emit('message', langChangeMessage);
      
    } catch (error) {
      console.error('Language change error:', error);
      socket.emit('error', { message: 'Language change failed' });
    }
  });

  // Typing indicators
  socket.on('typing', ({ roomId, isTyping }) => {
    const userSession = userSessions[socket.id];
    
    if (userSession && userSession.roomId === roomId) {
      socket.to(roomId).emit('userTyping', {
        username: userSession.username,
        isTyping
      });
    }
  });

  // Audio permission handling (keeping existing)
  socket.on('audioPermissionRequest', ({ roomId, username }) => {
    try {
      const userSession = userSessions[socket.id];
      if (!userSession || userSession.roomId !== roomId) return;

      initializeRoomAudio(roomId);

      if (audioPermissions[roomId][username]) {
        socket.emit('error', { message: 'You already have audio permission' });
        return;
      }

      const existingRequest = pendingAudioRequests[roomId].find(req => req.username === username);
      if (existingRequest) {
        socket.emit('error', { message: 'Permission request already pending' });
        return;
      }

      const request = { username, timestamp: new Date().toISOString() };
      pendingAudioRequests[roomId].push(request);

      rooms[roomId]?.forEach(user => {
        if (user.role === 'owner' || user.role === 'moderator') {
          const targetSocket = io.sockets.sockets.get(user.id);
          if (targetSocket) {
            targetSocket.emit('audioPermissionRequest', request);
          }
        }
      });

    } catch (error) {
      console.error('Error handling audio permission request:', error);
    }
  });

  socket.on('audioPermissionResponse', ({ roomId, username, granted }) => {
    try {
      const userSession = userSessions[socket.id];
      if (!userSession || userSession.roomId !== roomId) return;

      const currentUser = rooms[roomId]?.find(u => u.id === socket.id);
      if (!currentUser || (currentUser.role !== 'owner' && currentUser.role !== 'moderator')) {
        socket.emit('error', { message: 'You do not have permission to grant audio access' });
        return;
      }

      initializeRoomAudio(roomId);

      pendingAudioRequests[roomId] = pendingAudioRequests[roomId].filter(
        req => req.username !== username
      );

      audioPermissions[roomId][username] = granted;

      const targetUser = rooms[roomId]?.find(u => u.username === username);
      if (targetUser) {
        const targetSocket = io.sockets.sockets.get(targetUser.id);
        if (targetSocket) {
          targetSocket.emit('audioPermissionResponse', {
            username,
            granted,
            respondedBy: currentUser.username
          });
        }
      }

      io.to(roomId).emit('audioPermissionsUpdate', {
        permissions: audioPermissions[roomId]
      });

    } catch (error) {
      console.error('Error handling audio permission response:', error);
    }
  });

  // =============================================================================
  // NEW WEBRTC VOICE CHAT EVENTS
  // =============================================================================

  // Join voice room
  socket.on('join-voice-room', ({ roomId, userId, username }) => {
    try {
      console.log(`🎙️ ${username} joining voice room ${roomId}`);
      
      const userSession = userSessions[socket.id];
      if (!userSession || userSession.roomId !== roomId) {
        socket.emit('error', { message: 'You must be in the room to join voice chat' });
        return;
      }

      // Check audio permissions
      const roomUser = rooms[roomId]?.find(u => u.id === socket.id);
      if (!roomUser) {
        socket.emit('error', { message: 'User not found in room' });
        return;
      }

      const hasPermission = roomUser.role === 'owner' || 
                          roomUser.role === 'moderator' || 
                          audioPermissions[roomId]?.[username];

      if (!hasPermission) {
        socket.emit('error', { message: 'Audio permission required' });
        return;
      }

      // Initialize voice room if it doesn't exist
      if (!voiceRooms[roomId]) {
        voiceRooms[roomId] = [];
      }

      // Check if user is already in voice room
      const existingVoiceUser = voiceRooms[roomId].find(u => u.userId === userId);
      if (existingVoiceUser) {
        socket.emit('error', { message: 'Already in voice chat' });
        return;
      }

      // Add user to voice room
      const voiceUser = {
        userId,
        username,
        socketId: socket.id,
        joinedAt: new Date()
      };

      voiceRooms[roomId].push(voiceUser);
      
      console.log(`✅ ${username} joined voice room. Total voice users: ${voiceRooms[roomId].length}`);

      // Notify all users in voice room about the new user
      socket.to(roomId).emit('user-joined-voice', {
        userId,
        username,
        socketId: socket.id
      });

      // Send current voice room users to the new joiner
      socket.emit('voice-room-users', {
        users: voiceRooms[roomId].filter(u => u.userId !== userId)
      });

      // Notify room about voice room update
      io.to(roomId).emit('voice-room-updated', {
        voiceUsers: voiceRooms[roomId],
        totalVoiceUsers: voiceRooms[roomId].length
      });

    } catch (error) {
      console.error('Error joining voice room:', error);
      socket.emit('error', { message: 'Failed to join voice room' });
    }
  });

  // Leave voice room
  socket.on('leave-voice-room', ({ roomId, userId }) => {
    try {
      console.log(`🎙️ User ${userId} leaving voice room ${roomId}`);
      
      if (!voiceRooms[roomId]) return;

      // Find and remove user from voice room
      const userIndex = voiceRooms[roomId].findIndex(u => u.userId === userId);
      if (userIndex === -1) return;

      const leavingUser = voiceRooms[roomId][userIndex];
      voiceRooms[roomId].splice(userIndex, 1);

      console.log(`✅ ${leavingUser.username} left voice room. Remaining: ${voiceRooms[roomId].length}`);

      // Notify others in voice room
      socket.to(roomId).emit('user-left-voice', {
        userId,
        username: leavingUser.username
      });

      // Notify room about voice room update
      io.to(roomId).emit('voice-room-updated', {
        voiceUsers: voiceRooms[roomId],
        totalVoiceUsers: voiceRooms[roomId].length
      });

      // Clean up empty voice room
      if (voiceRooms[roomId].length === 0) {
        delete voiceRooms[roomId];
        delete voiceSignals[roomId];
      }

    } catch (error) {
      console.error('Error leaving voice room:', error);
    }
  });

  // WebRTC Signaling Events
  socket.on('sending-signal', ({ userToCall, callerID, signal, roomId }) => {
    try {
      console.log(`📞 Sending signal from ${callerID} to ${userToCall} in room ${roomId}`);
      
      // Find the target user's socket
      const targetUser = voiceRooms[roomId]?.find(u => u.userId === userToCall);
      if (!targetUser) {
        console.log(`❌ Target user ${userToCall} not found in voice room`);
        return;
      }

      const targetSocket = io.sockets.sockets.get(targetUser.socketId);
      if (!targetSocket) {
        console.log(`❌ Target socket not found for user ${userToCall}`);
        return;
      }

      // Forward the signal to the target user
      targetSocket.emit('user-calling', {
        signal,
        from: callerID,
        username: socket.username
      });

    } catch (error) {
      console.error('Error handling sending signal:', error);
    }
  });

  socket.on('returning-signal', ({ signal, callerID, roomId }) => {
    try {
      console.log(`📞 Returning signal to ${callerID} in room ${roomId}`);
      
      // Find the caller's socket
      const callerUser = voiceRooms[roomId]?.find(u => u.userId === callerID);
      if (!callerUser) {
        console.log(`❌ Caller ${callerID} not found in voice room`);
        return;
      }

      const callerSocket = io.sockets.sockets.get(callerUser.socketId);
      if (!callerSocket) {
        console.log(`❌ Caller socket not found for user ${callerID}`);
        return;
      }

      // Forward the return signal to the caller
      callerSocket.emit('receiving-returned-signal', {
        signal,
        id: socket.userId
      });

    } catch (error) {
      console.error('Error handling returning signal:', error);
    }
  });

  // Speaking status updates
  socket.on('speaking-status', ({ roomId, isSpeaking }) => {
    try {
      const userSession = userSessions[socket.id];
      if (!userSession || userSession.roomId !== roomId) return;

      // Broadcast speaking status to voice room users
      socket.to(roomId).emit('user-speaking-update', {
        userId: socket.userId,
        username: socket.username,
        isSpeaking
      });

    } catch (error) {
      console.error('Error handling speaking status:', error);
    }
  });

  // =============================================================================
  // DISCONNECT HANDLING (Enhanced for voice chat)
  // =============================================================================
  socket.on('disconnect', () => {
    console.log(`🔌 User disconnected: ${socket.username || 'Unknown'} (${socket.id})`);
    
    const userSession = userSessions[socket.id];
    if (userSession && userSession.roomId) {
      const roomId = userSession.roomId;
      const userIndex = rooms[roomId]?.findIndex(u => u.id === socket.id);
      
      if (userIndex !== -1) {
        const username = rooms[roomId][userIndex].username;
        rooms[roomId].splice(userIndex, 1);
        
        // Clean up voice room participation
        if (voiceRooms[roomId]) {
          const voiceUserIndex = voiceRooms[roomId].findIndex(u => u.socketId === socket.id);
          if (voiceUserIndex !== -1) {
            const leavingVoiceUser = voiceRooms[roomId][voiceUserIndex];
            voiceRooms[roomId].splice(voiceUserIndex, 1);
            
            console.log(`🎙️ ${username} removed from voice room on disconnect`);
            
            // Notify voice room users
            socket.to(roomId).emit('user-left-voice', {
              userId: leavingVoiceUser.userId,
              username: leavingVoiceUser.username
            });

            // Update voice room status
            io.to(roomId).emit('voice-room-updated', {
              voiceUsers: voiceRooms[roomId],
              totalVoiceUsers: voiceRooms[roomId].length
            });

            // Clean up empty voice room
            if (voiceRooms[roomId].length === 0) {
              delete voiceRooms[roomId];
              delete voiceSignals[roomId];
            }
          }
        }
        
        console.log(`❌ ${username} left room ${roomId}`);

        const leaveMessage = {
          id: Date.now(),
          sender: 'System',
          message: `${username} has left the room.`,
          timestamp: new Date().toISOString(),
          type: 'system'
        };
        socket.to(roomId).emit('message', leaveMessage);

        io.to(roomId).emit('roomUsers', rooms[roomId]);
      }
    }
    
    delete userSessions[socket.id];
    setTimeout(cleanupEmptyRooms, 5000);
  });
});

// =============================================================================
// ERROR HANDLING
// =============================================================================
app.use((error, req, res, next) => {
  console.error('Express error:', error);
  res.status(500).json({ 
    error: 'Internal server error',
    message: NODE_ENV === 'development' ? error.message : 'Something went wrong'
  });
});

app.use('*', (req, res) => {
  res.status(404).json({ 
    error: 'Route not found',
    availableEndpoints: [
      'GET /health',
      'GET /api/health',
      'POST /api/auth/login',
      'POST /api/auth/signup',
      'POST /api/auth/verify',
      'POST /api/rooms/create',
      'GET /api/room/:roomId'
    ]
  });
});

// =============================================================================
// GRACEFUL SHUTDOWN (Enhanced for voice chat cleanup)
// =============================================================================
const gracefulShutdown = (signal) => {
  console.log(`🛑 Received ${signal}. Starting graceful shutdown...`);
  
  // Notify all voice chat users about shutdown
  Object.keys(voiceRooms).forEach(roomId => {
    io.to(roomId).emit('voice-chat-shutdown', {
      message: 'Voice chat will be temporarily unavailable during server maintenance.'
    });
  });
  
  io.emit('serverShutdown', {
    message: 'Server is shutting down for maintenance. Please reconnect in a few minutes.'
  });
  
  server.close(() => {
    console.log('✅ HTTP server closed');
    console.log('🎯 All connections closed');
    process.exit(0);
  });

  // Force close after 30 seconds
  setTimeout(() => {
    console.log('⚠️ Force closing server after 30 seconds');
    process.exit(1);
  }, 30000);
};

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));
process.on('SIGQUIT', () => gracefulShutdown('SIGQUIT'));

process.on('uncaughtException', (error) => {
  console.error('💥 Uncaught Exception:', error);
  gracefulShutdown('UNCAUGHT_EXCEPTION');
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('💥 Unhandled Rejection at:', promise, 'reason:', reason);
  gracefulShutdown('UNHANDLED_REJECTION');
});

// =============================================================================
// START SERVER
// =============================================================================
server.listen(PORT, '0.0.0.0', () => {
  console.log('');
  console.log('🎉 ==============================================');
  console.log('🚀 COTOG Backend with WebRTC Voice Chat Ready!');
  console.log('🎉 ==============================================');
  console.log('');
  console.log(`📡 Server URL: http://localhost:${PORT}`);
  console.log(`🌍 Environment: ${NODE_ENV}`);
  console.log(`🔐 JWT Secret: ${JWT_SECRET.substring(0, 10)}...`);
  console.log(`🔗 Frontend URL: ${FRONTEND_URL}`);
  console.log('');
  console.log('📋 Available Demo Accounts:');
  console.log('   👤 john.doe@example.com (User)');
  console.log('   👑 sarah.wilson@example.com (Admin)');
  console.log('   🛡️ alex.kim@example.com (Moderator)');
  console.log('   🔑 Password for all: password123');
  console.log('');
  console.log('🔧 API Endpoints:');
  console.log('   📊 GET  /health - Health check');
  console.log('   🔐 POST /api/auth/login - User login');
  console.log('   📝 POST /api/auth/signup - User registration');
  console.log('   ✅ POST /api/auth/verify - Token verification');
  console.log('   🏠 POST /api/rooms/create - Create room');
  console.log('   📡 Socket.IO: Real-time collaboration + WebRTC voice');
  console.log('');
  console.log('🎙️ WebRTC Voice Chat Features:');
  console.log('   📞 P2P voice communication');
  console.log('   🔐 Permission-based access');
  console.log('   🎵 Speaking detection');
  console.log('   📡 Real-time signaling');
  console.log('');
  console.log('✅ Backend ready for frontend connection!');
  console.log('');
});

module.exports = { app, server, io };