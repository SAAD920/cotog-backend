// server.js - ROLE SYSTEM INDICATORS REMOVED
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
const FRONTEND_URL = process.env.FRONTEND_URL || 'https://cotog-collaborative-editor-222.onrender.com';

console.log('🚀 COTOG Backend Starting...');
console.log('📊 Environment:', NODE_ENV);
console.log('🌍 Port:', PORT);
console.log('🔗 Frontend URL:', FRONTEND_URL);

// =============================================================================
// CORS CONFIGURATION
// =============================================================================
const corsOptions = {
  origin: [
    FRONTEND_URL,
    'https://cotog-collaborative-editor-222.onrender.com',
    'https://cotog-frontend.onrender.com',
    'https://cotog-backend.onrender.com',
    'http://127.0.0.1:3000',
    'http://localhost:3000',
    /\.onrender\.com$/,
    /\.vercel\.app$/,
    /\.netlify\.app$/,
    /\.render\.com$/,
    /^http:\/\/localhost:[0-9]+$/,
    /^http:\/\/127\.0\.0\.1:[0-9]+$/
  ],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  credentials: true,
  optionsSuccessStatus: 200,
  allowedHeaders: [
    'Content-Type', 
    'Authorization', 
    'x-requested-with',
    'Accept',
    'Origin',
    'Access-Control-Request-Method',
    'Access-Control-Request-Headers'
  ]
};

// =============================================================================
// SOCKET.IO CONFIGURATION
// =============================================================================
const io = new Server(server, {
  cors: corsOptions,
  transports: ['websocket', 'polling'],
  allowEIO3: true,
  pingTimeout: 60000,
  pingInterval: 25000,
  upgradeTimeout: 30000,
  maxHttpBufferSize: 2e6,
  compression: true,
  cookie: false,
  serveClient: false,
  connectTimeout: 45000,
  binary: true
});

// =============================================================================
// EXPRESS MIDDLEWARE
// =============================================================================
app.use(cors(corsOptions));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.set('trust proxy', 1);

// Enhanced CORS handling
app.use((req, res, next) => {
  const origin = req.headers.origin;
  console.log(`📡 Request from origin: ${origin}`);
  
  const allowedOrigins = [
    FRONTEND_URL,
    'https://cotog-collaborative-editor-222.onrender.com',
    'https://cotog-frontend.onrender.com',
    'https://cotog-backend.onrender.com',
    'http://localhost:3000',
    'http://127.0.0.1:3000'
  ];
  
  if (allowedOrigins.includes(origin) || (origin && /\.onrender\.com$/.test(origin))) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    console.log(`✅ CORS allowed for origin: ${origin}`);
  } else if (origin) {
    console.log(`❌ CORS denied for origin: ${origin}`);
  }
  
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, x-requested-with, Accept, Origin');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Max-Age', '86400');
  
  if (req.method === 'OPTIONS') {
    console.log(`📄 CORS preflight request from: ${origin}`);
    res.status(200).end();
    return;
  }
  
  next();
});

// Security headers
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Feature-Policy', 'microphone *; camera *');
  res.setHeader('Permissions-Policy', 'microphone=*, camera=*');
  next();
});

// =============================================================================
// DATA STORES
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
    role: 'user',
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
    role: 'user',
    createdAt: new Date('2024-02-15T08:30:00Z'),
    lastLogin: new Date(),
    isActive: true,
    preferences: { theme: 'dark', language: 'java' }
  }
];

// Room management
const rooms = {}; // { roomId: [ { id, username, userId, joinedAt, roomRole } ] }
const roomsData = {}; // Room metadata
const messageHistory = {}; // Chat history
const userSessions = {}; // Socket sessions

// WebRTC voice chat system
const voiceRooms = {}; // { roomId: [ { userId, username, socketId, joinedAt } ] }
const activePeers = {}; // { roomId: { userId: [connectedUserIds] } }

// ICE servers configuration for WebRTC
const iceServers = [
  { urls: 'stun:stun.l.google.com:19302' },
  { urls: 'stun:stun1.l.google.com:19302' },
  { urls: 'stun:stun2.l.google.com:19302' },
  { urls: 'stun:global.stun.twilio.com:3478' }
];

// WebRTC configuration
const webrtcConfig = {
  iceServers,
  iceCandidatePoolSize: 10,
  bundlePolicy: 'balanced',
  rtcpMuxPolicy: 'require',
  sdpSemantics: 'unified-plan'
};

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
    socket.webrtcSessionId = `${user.id}_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
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
      delete voiceRooms[roomId];
      delete activePeers[roomId];
      console.log(`🧹 Cleaned up empty room: ${roomId}`);
    }
  }
};

// =============================================================================
// API ROUTES
// =============================================================================

// Root endpoint
app.get('/', (req, res) => {
  res.json({
    message: 'COTOG Backend API',
    status: 'running',
    version: '5.0.0',
    environment: NODE_ENV,
    timestamp: new Date().toISOString(),
    roleSystem: {
      description: 'User role + room creator privileges',
      userRole: 'Standard user - can join rooms, edit code, chat, voice',
      roomCreator: 'Room owner - has language control and room management'
    },
    endpoints: {
      health: '/health',
      apiHealth: '/api/health',
      auth: '/api/auth/*',
      rooms: '/api/rooms/*',
      voiceChatStatus: '/api/voice-chat/status',
      webrtcConfig: '/api/webrtc/config',
      roomVoiceStatus: '/api/room/:roomId/voice-status'
    },
    features: {
      websocket: 'Socket.IO v4 enabled',
      webrtc: 'Enhanced P2P voice chat',
      cors: 'Multi-origin enabled',
      signaling: 'Enhanced WebRTC signaling'
    }
  });
});

// Health check
app.get('/health', (req, res) => {
  const uptime = process.uptime();
  const memoryUsage = process.memoryUsage();
  
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: uptime,
    uptimeFormatted: `${Math.floor(uptime / 3600)}h ${Math.floor((uptime % 3600) / 60)}m ${Math.floor(uptime % 60)}s`,
    environment: NODE_ENV,
    version: '5.0.0',
    memory: {
      rss: `${Math.round(memoryUsage.rss / 1024 / 1024)} MB`,
      heapTotal: `${Math.round(memoryUsage.heapTotal / 1024 / 1024)} MB`,
      heapUsed: `${Math.round(memoryUsage.heapUsed / 1024 / 1024)} MB`,
      external: `${Math.round(memoryUsage.external / 1024 / 1024)} MB`
    },
    activeRooms: Object.keys(roomsData).length,
    activeSessions: Object.keys(userSessions).length,
    voiceRooms: Object.keys(voiceRooms).length,
    voiceUsers: Object.values(voiceRooms).reduce((sum, room) => sum + room.length, 0),
    peerConnections: Object.values(activePeers).reduce((sum, room) => Object.keys(room).length + sum, 0),
    frontendUrl: FRONTEND_URL,
    corsEnabled: true,
    webrtcEnabled: true
  });
});

// Authentication routes
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password, rememberMe } = req.body;
    console.log(`🔐 Login attempt for: ${email}`);

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const user = await userService.validateCredentials(email, password);
    
    if (!user) {
      console.log(`❌ Login failed for: ${email}`);
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    userService.updateLastLogin(user.id);

    const tokenExpiry = rememberMe ? '30d' : '24h';
    const token = jwt.sign(
      { userId: user.id, email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: tokenExpiry }
    );

    console.log(`✅ Login successful for: ${email}`);

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

// Room creation
app.post('/api/rooms/create', authenticateToken, (req, res) => {
  try {
    const { roomName, password, maxUsers, isPrivate, description } = req.body;
    const userId = req.user.userId;
    
    console.log(`🏠 Room creation attempt by user ${userId}`);
    
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
      currentCode: '// Welcome to collaborative coding!\n// Start typing to share your code with the team...',
      webrtcConfig: webrtcConfig
    };
    
    rooms[roomId] = [];
    messageHistory[roomId] = [];
    
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
        currentLanguage: roomsData[roomId].currentLanguage,
        webrtcEnabled: true
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
      currentLanguage: room.currentLanguage,
      voiceUsers: voiceRooms[roomId]?.length || 0,
      webrtcEnabled: true,
      webrtcConfig: webrtcConfig
    });

  } catch (error) {
    console.error('Room info error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// =============================================================================
// SOCKET.IO CONNECTION HANDLING
// =============================================================================
io.use(authenticateSocket);

io.on('connection', (socket) => {
  console.log(`🔌 User connected: ${socket.username} (${socket.id}) from ${socket.handshake.headers.origin}`);

  userSessions[socket.id] = {
    userId: socket.userId,
    username: socket.username,
    userRole: socket.userRole,
    roomId: null,
    connectedAt: new Date(),
    webrtcSessionId: socket.webrtcSessionId,
    browser: socket.handshake.headers['user-agent']?.includes('Chrome') ? 'Chrome' : 'Other'
  };

  // Join room
  socket.on('joinRoom', ({ roomId, roomPassword }) => {
    try {
      console.log(`🚪 User ${socket.username} attempting to join room ${roomId}`);
      
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
      
      // Determine room role: 'owner' (room creator) or 'member'
      let roomRole = 'member';
      if (room.createdBy === socket.userId) {
        roomRole = 'owner';
      }
      
      if (!rooms[roomId]) rooms[roomId] = [];
      rooms[roomId].push({ 
        id: socket.id, 
        userId: socket.userId,
        username: socket.username,
        joinedAt: new Date(),
        roomRole: roomRole,
        webrtcSessionId: socket.webrtcSessionId
      });

      console.log(`🔥 ${socket.username} joined room ${roomId} as ${roomRole}`);

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
        userRole: roomRole,
        webrtcSessionId: socket.webrtcSessionId,
        roomInfo: {
          roomName: room.roomName,
          maxUsers: room.maxUsers,
          currentUsers: rooms[roomId].length,
          description: room.description,
          isPrivate: room.isPrivate,
          currentLanguage: room.currentLanguage,
          webrtcEnabled: true
        },
        webrtcConfig: webrtcConfig
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
        senderRole: user.roomRole
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

  // Language changes - Only room owner can change language
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
      
      // Only room owner (creator) can change language
      if (user.roomRole !== 'owner') {
        socket.emit('error', { message: 'Only room creator can change language' });
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
        message: `${user.username} (room creator) changed the coding language to ${language.toUpperCase()}`,
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

  // WebRTC voice chat events
  socket.on('join-voice-room', ({ roomId, userInfo }) => {
    try {
      console.log(`🎙️ ${userInfo.username} joining voice room ${roomId}`);
      
      const userSession = userSessions[socket.id];
      if (!userSession || userSession.roomId !== roomId) {
        socket.emit('error', { message: 'You must be in the room to join voice chat' });
        return;
      }

      if (!voiceRooms[roomId]) {
        voiceRooms[roomId] = [];
        activePeers[roomId] = {};
      }

      const existingIndex = voiceRooms[roomId].findIndex(u => u.userId === userInfo.userId);
      if (existingIndex !== -1) {
        voiceRooms[roomId][existingIndex] = {
          ...voiceRooms[roomId][existingIndex],
          socketId: socket.id,
          reconnectedAt: new Date()
        };
        console.log(`🔄 Updated connection info for ${userInfo.username}`);
      } else {
        const voiceUser = {
          userId: userInfo.userId,
          username: userInfo.username,
          socketId: socket.id,
          joinedAt: new Date()
        };
        voiceRooms[roomId].push(voiceUser);
        
        if (!activePeers[roomId][userInfo.userId]) {
          activePeers[roomId][userInfo.userId] = [];
        }
      }

      console.log(`✅ ${userInfo.username} in voice room. Total: ${voiceRooms[roomId].length}`);

      voiceRooms[roomId] = voiceRooms[roomId].filter(voiceUser => {
        const targetSocket = io.sockets.sockets.get(voiceUser.socketId);
        const isActive = targetSocket && targetSocket.connected;
        
        if (!isActive && voiceUser.userId !== userInfo.userId) {
          console.log(`🧹 Removing stale voice user: ${voiceUser.username}`);
          if (activePeers[roomId][voiceUser.userId]) {
            delete activePeers[roomId][voiceUser.userId];
          }
        }
        
        return isActive || voiceUser.userId === userInfo.userId;
      });

      const otherUsers = voiceRooms[roomId].filter(u => u.userId !== userInfo.userId);
      
      if (otherUsers.length > 0) {
        console.log(`📡 Sending ${otherUsers.length} existing voice users to ${userInfo.username}`);
        socket.emit('voice-room-users', {
          users: otherUsers.map(u => ({
            userId: u.userId,
            username: u.username
          }))
        });
      }

      setTimeout(() => {
        const currentOtherUsers = voiceRooms[roomId].filter(u => u.userId !== userInfo.userId);
        
        currentOtherUsers.forEach((existingUser, index) => {
          const targetSocket = io.sockets.sockets.get(existingUser.socketId);
          if (targetSocket && targetSocket.connected) {
            setTimeout(() => {
              targetSocket.emit('user-joined-voice', {
                userInfo: {
                  userId: userInfo.userId,
                  username: userInfo.username
                }
              });
              console.log(`📡 Notified ${existingUser.username} about ${userInfo.username} joining`);
            }, index * 1000);
          }
        });
      }, 2000);

      socket.emit('voice-room-joined', {
        roomId,
        userInfo,
        existingUsers: otherUsers.length,
        totalUsers: voiceRooms[roomId].length
      });

    } catch (error) {
      console.error('❌ Error joining voice room:', error);
      socket.emit('error', { message: 'Failed to join voice room' });
    }
  });

  // Leave voice room
  socket.on('leave-voice-room', ({ roomId, userInfo }) => {
    try {
      console.log(`🎙️ ${userInfo.username} leaving voice room ${roomId}`);
      
      if (!voiceRooms[roomId]) {
        console.log(`❌ Voice room ${roomId} not found`);
        return;
      }

      const userIndex = voiceRooms[roomId].findIndex(u => u.userId === userInfo.userId);
      if (userIndex === -1) {
        console.log(`❌ User ${userInfo.username} not found in voice room`);
        return;
      }

      const leavingUser = voiceRooms[roomId][userIndex];
      voiceRooms[roomId].splice(userIndex, 1);

      if (activePeers[roomId] && activePeers[roomId][userInfo.userId]) {
        delete activePeers[roomId][userInfo.userId];
      }

      Object.keys(activePeers[roomId] || {}).forEach(otherUserId => {
        if (activePeers[roomId][otherUserId]) {
          activePeers[roomId][otherUserId] = activePeers[roomId][otherUserId].filter(
            peerId => peerId !== userInfo.userId
          );
        }
      });

      console.log(`✅ ${userInfo.username} left voice room. Remaining: ${voiceRooms[roomId].length}`);

      const remainingUsers = voiceRooms[roomId];
      remainingUsers.forEach((user, index) => {
        const targetSocket = io.sockets.sockets.get(user.socketId);
        if (targetSocket && targetSocket.connected) {
          setTimeout(() => {
            targetSocket.emit('user-left-voice', {
              userInfo: {
                userId: userInfo.userId,
                username: userInfo.username
              },
              reason: 'user_left',
              timestamp: Date.now()
            });
          }, index * 100);
        }
      });

      socket.emit('voice-room-left', {
        roomId,
        userInfo,
        remainingUsers: remainingUsers.length
      });

      if (voiceRooms[roomId].length === 0) {
        delete voiceRooms[roomId];
        delete activePeers[roomId];
        console.log(`🧹 Cleaned up empty voice room: ${roomId}`);
      }

    } catch (error) {
      console.error('❌ Error leaving voice room:', error);
      socket.emit('error', { message: 'Failed to leave voice room' });
    }
  });

  // WebRTC signaling
  socket.on('webrtc-signal', ({ targetUserId, signal, callerInfo, roomId }) => {
    try {
      console.log(`📞 WebRTC signal from ${callerInfo.username} to ${targetUserId} (type: ${signal?.type})`);
      
      if (!signal || !targetUserId || !callerInfo || !roomId) {
        console.error('❌ Invalid WebRTC signal data');
        socket.emit('webrtc-error', { 
          message: 'Invalid signal data',
          targetUserId 
        });
        return;
      }

      if (!voiceRooms[roomId] || !voiceRooms[roomId].find(u => u.userId === callerInfo.userId)) {
        console.error(`❌ Caller ${callerInfo.username} not in voice room`);
        socket.emit('webrtc-error', { 
          message: 'You are not in the voice room',
          targetUserId,
          details: 'Please join voice chat first'
        });
        return;
      }

      const targetUser = voiceRooms[roomId].find(u => u.userId === targetUserId);
      if (!targetUser) {
        console.error(`❌ Target user ${targetUserId} not found in voice room`);
        socket.emit('webrtc-error', { 
          message: `User not available for voice chat`,
          targetUserId,
          details: 'Target user may have left voice chat'
        });
        return;
      }

      const targetSocket = io.sockets.sockets.get(targetUser.socketId);
      if (!targetSocket || !targetSocket.connected) {
        console.error(`❌ Target user ${targetUser.username} socket not available`);
        
        voiceRooms[roomId] = voiceRooms[roomId].filter(u => u.userId !== targetUserId);
        
        socket.emit('webrtc-error', { 
          message: `User ${targetUser.username} is no longer available`,
          targetUserId,
          details: 'Connection lost'
        });
        return;
      }

      if (!activePeers[roomId]) activePeers[roomId] = {};
      if (!activePeers[roomId][callerInfo.userId]) activePeers[roomId][callerInfo.userId] = [];
      
      if (!activePeers[roomId][callerInfo.userId].includes(targetUserId)) {
        activePeers[roomId][callerInfo.userId].push(targetUserId);
      }

      const signalData = {
        signal,
        callerInfo: {
          userId: callerInfo.userId,
          username: callerInfo.username
        },
        roomId,
        timestamp: Date.now(),
        serverProcessed: true
      };

      console.log(`📡 Forwarding WebRTC signal to ${targetUser.username}`);
      targetSocket.emit('webrtc-signal', signalData);

      socket.emit('webrtc-signal-sent', {
        targetUserId,
        signalType: signal.type,
        timestamp: Date.now(),
        targetUsername: targetUser.username
      });

    } catch (error) {
      console.error('❌ Error handling WebRTC signal:', error);
      socket.emit('webrtc-error', { 
        message: 'Failed to send signal',
        targetUserId,
        error: error.message,
        details: 'Server processing error'
      });
    }
  });

  // WebRTC answer
  socket.on('webrtc-answer', ({ targetUserId, signal, answererInfo, roomId }) => {
    try {
      console.log(`📞 WebRTC answer from ${answererInfo.username} to ${targetUserId} (type: ${signal?.type})`);
      
      if (!signal || !targetUserId || !answererInfo || !roomId) {
        console.error('❌ Invalid WebRTC answer data');
        socket.emit('webrtc-error', { 
          message: 'Invalid answer data',
          targetUserId,
          details: 'Missing required fields'
        });
        return;
      }

      if (!voiceRooms[roomId] || !voiceRooms[roomId].find(u => u.userId === answererInfo.userId)) {
        console.error(`❌ Answerer ${answererInfo.username} not in voice room`);
        socket.emit('webrtc-error', { 
          message: 'You are not in the voice room',
          targetUserId,
          details: 'Please rejoin voice chat'
        });
        return;
      }

      const targetUser = voiceRooms[roomId].find(u => u.userId === targetUserId);
      if (!targetUser) {
        console.error(`❌ Target user ${targetUserId} not found in voice room`);
        socket.emit('webrtc-error', { 
          message: `Original caller not found`,
          targetUserId,
          details: 'Caller may have left voice chat'
        });
        return;
      }

      const targetSocket = io.sockets.sockets.get(targetUser.socketId);
      if (!targetSocket || !targetSocket.connected) {
        console.error(`❌ Target user ${targetUser.username} socket not available`);
        
        voiceRooms[roomId] = voiceRooms[roomId].filter(u => u.userId !== targetUserId);
        
        socket.emit('webrtc-error', { 
          message: `Original caller ${targetUser.username} is no longer available`,
          targetUserId,
          details: 'Connection lost during handshake'
        });
        return;
      }

      if (!activePeers[roomId]) activePeers[roomId] = {};
      if (!activePeers[roomId][answererInfo.userId]) activePeers[roomId][answererInfo.userId] = [];
      
      if (!activePeers[roomId][answererInfo.userId].includes(targetUserId)) {
        activePeers[roomId][answererInfo.userId].push(targetUserId);
      }

      const answerData = {
        signal,
        answererInfo: {
          userId: answererInfo.userId,
          username: answererInfo.username
        },
        roomId,
        timestamp: Date.now(),
        serverProcessed: true
      };

      console.log(`📡 Forwarding WebRTC answer to ${targetUser.username}`);
      targetSocket.emit('webrtc-answer', answerData);

      socket.emit('webrtc-answer-sent', {
        targetUserId,
        signalType: signal.type,
        timestamp: Date.now(),
        targetUsername: targetUser.username
      });

      console.log(`✅ WebRTC handshake completed between ${answererInfo.username} and ${targetUser.username}`);

    } catch (error) {
      console.error('❌ Error handling WebRTC answer:', error);
      socket.emit('webrtc-error', { 
        message: 'Failed to send answer',
        targetUserId,
        error: error.message,
        details: 'Server processing error'
      });
    }
  });

  // Enhanced disconnect handling
  socket.on('disconnect', (reason) => {
    console.log(`🔌 User disconnected: ${socket.username || 'Unknown'} (${socket.id}) - Reason: ${reason}`);
    
    const userSession = userSessions[socket.id];
    if (userSession && userSession.roomId) {
      const roomId = userSession.roomId;
      const userId = userSession.userId;
      const username = userSession.username;
      
      // Clean up from regular room
      const userIndex = rooms[roomId]?.findIndex(u => u.id === socket.id);
      if (userIndex !== -1) {
        rooms[roomId].splice(userIndex, 1);
        
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

      // Clean up from voice room
      if (voiceRooms[roomId]) {
        const voiceUserIndex = voiceRooms[roomId].findIndex(u => u.socketId === socket.id);
        if (voiceUserIndex !== -1) {
          const leavingVoiceUser = voiceRooms[roomId][voiceUserIndex];
          voiceRooms[roomId].splice(voiceUserIndex, 1);
          
          console.log(`🎙️ ${leavingVoiceUser.username} removed from voice room on disconnect`);
          
          if (activePeers[roomId] && activePeers[roomId][userId]) {
            delete activePeers[roomId][userId];
          }

          Object.keys(activePeers[roomId] || {}).forEach(otherUserId => {
            if (activePeers[roomId][otherUserId]) {
              activePeers[roomId][otherUserId] = activePeers[roomId][otherUserId].filter(
                peerId => peerId !== userId
              );
            }
          });
          
          const remainingVoiceUsers = voiceRooms[roomId];
          remainingVoiceUsers.forEach((voiceUser, index) => {
            const targetSocket = io.sockets.sockets.get(voiceUser.socketId);
            if (targetSocket && targetSocket.connected) {
              setTimeout(() => {
                targetSocket.emit('user-left-voice', {
                  userInfo: {
                    userId: leavingVoiceUser.userId,
                    username: leavingVoiceUser.username
                  },
                  reason: 'disconnected',
                  timestamp: Date.now()
                });
              }, index * 200);
            }
          });

          setTimeout(() => {
            io.to(roomId).emit('voice-room-status', {
              totalVoiceUsers: voiceRooms[roomId].length,
              voiceUsers: voiceRooms[roomId].map(u => ({
                userId: u.userId,
                username: u.username
              })),
              timestamp: Date.now()
            });
          }, 1000);

          if (voiceRooms[roomId].length === 0) {
            delete voiceRooms[roomId];
            delete activePeers[roomId];
            console.log(`🧹 Cleaned up empty voice room: ${roomId}`);
          }
        }
      }
    }
    
    delete userSessions[socket.id];
    setTimeout(cleanupEmptyRooms, 5000);
  });
});

// Periodic cleanup
setInterval(() => {
  Object.keys(voiceRooms).forEach(roomId => {
    if (!voiceRooms[roomId]) return;
    
    const beforeCount = voiceRooms[roomId].length;
    
    voiceRooms[roomId] = voiceRooms[roomId].filter(voiceUser => {
      const socket = io.sockets.sockets.get(voiceUser.socketId);
      const isActive = socket && socket.connected;
      
      if (!isActive) {
        console.log(`🧹 Removing stale voice user: ${voiceUser.username} from room ${roomId}`);
        
        if (activePeers[roomId] && activePeers[roomId][voiceUser.userId]) {
          delete activePeers[roomId][voiceUser.userId];
        }
        
        Object.keys(activePeers[roomId] || {}).forEach(otherUserId => {
          if (activePeers[roomId][otherUserId]) {
            activePeers[roomId][otherUserId] = activePeers[roomId][otherUserId].filter(
              peerId => peerId !== voiceUser.userId
            );
          }
        });
      }
      
      return isActive;
    });
    
    const afterCount = voiceRooms[roomId].length;
    
    if (beforeCount !== afterCount) {
      console.log(`🧹 Cleaned up ${beforeCount - afterCount} stale users from voice room ${roomId}`);
      
      if (afterCount > 0) {
        setTimeout(() => {
          io.to(roomId).emit('voice-room-status', {
            totalVoiceUsers: afterCount,
            voiceUsers: voiceRooms[roomId].map(u => ({
              userId: u.userId,
              username: u.username
            })),
            cleanupPerformed: true,
            timestamp: Date.now()
          });
        }, 500);
      }
    }
    
    if (voiceRooms[roomId].length === 0) {
      delete voiceRooms[roomId];
      delete activePeers[roomId];
      console.log(`🧹 Cleaned up empty voice room: ${roomId}`);
    }
  });
}, 45000);

// Enhanced logging for development
if (NODE_ENV === 'development') {
  setInterval(() => {
    const totalVoiceRooms = Object.keys(voiceRooms).length;
    const totalVoiceUsers = Object.values(voiceRooms).reduce((sum, room) => sum + room.length, 0);
    const totalPeerConnections = Object.values(activePeers).reduce((sum, room) => {
      return sum + Object.values(room).reduce((peerSum, peers) => peerSum + peers.length, 0);
    }, 0);
    
    if (totalVoiceUsers > 0) {
      console.log(`🎙️ Voice Chat Stats: ${totalVoiceRooms} rooms, ${totalVoiceUsers} users, ${totalPeerConnections} peer connections`);
      
      Object.entries(voiceRooms).forEach(([roomId, users]) => {
        const peerCount = Object.keys(activePeers[roomId] || {}).length;
        console.log(`   Room ${roomId}: ${users.length} users, ${peerCount} peer groups`);
      });
    }
  }, 60000);
}

// =============================================================================
// ERROR HANDLING
// =============================================================================
app.use((error, req, res, next) => {
  console.error('Express error:', error);
  res.status(500).json({ 
    error: 'Internal server error',
    message: NODE_ENV === 'development' ? error.message : 'Something went wrong',
    timestamp: new Date().toISOString(),
    version: '5.0.0'
  });
});

app.use('*', (req, res) => {
  res.status(404).json({ 
    error: 'Route not found',
    requestedPath: req.originalUrl,
    method: req.method,
    availableEndpoints: [
      'GET /',
      'GET /health',
      'GET /api/health',
      'POST /api/auth/login',
      'POST /api/auth/signup',
      'POST /api/auth/verify',
      'POST /api/rooms/create',
      'GET /api/room/:roomId'
    ],
    version: '5.0.0'
  });
});

// =============================================================================
// GRACEFUL SHUTDOWN
// =============================================================================
const gracefulShutdown = (signal) => {
  console.log(`🛑 Received ${signal}. Starting graceful shutdown...`);
  
  Object.entries(voiceRooms).forEach(([roomId, voiceUsers]) => {
    console.log(`📢 Notifying ${voiceUsers.length} voice users in room ${roomId} about shutdown`);
    
    voiceUsers.forEach(voiceUser => {
      const socket = io.sockets.sockets.get(voiceUser.socketId);
      if (socket && socket.connected) {
        socket.emit('voice-chat-shutdown', {
          message: 'Voice chat will be temporarily unavailable during server maintenance.',
          estimatedDowntime: '2-5 minutes',
          timestamp: new Date().toISOString(),
          reconnectInstructions: 'Please rejoin voice chat after the server restarts.'
        });
      }
    });
    
    io.to(roomId).emit('voice-chat-shutdown', {
      message: 'Voice chat will be temporarily unavailable during server maintenance.',
      estimatedDowntime: '2-5 minutes',
      timestamp: new Date().toISOString()
    });
  });
  
  io.emit('serverShutdown', {
    message: 'Server is shutting down for maintenance. Please reconnect in a few minutes.',
    timestamp: new Date().toISOString(),
    estimatedDowntime: '2-5 minutes'
  });

  console.log('📊 Final Statistics:');
  console.log(`   Active Rooms: ${Object.keys(roomsData).length}`);
  console.log(`   Active Users: ${Object.keys(userSessions).length}`);
  console.log(`   Voice Rooms: ${Object.keys(voiceRooms).length}`);
  console.log(`   Voice Users: ${Object.values(voiceRooms).reduce((sum, room) => sum + room.length, 0)}`);
  console.log(`   Peer Connections: ${Object.values(activePeers).reduce((sum, room) => Object.keys(room).length + sum, 0)}`);
  console.log(`   Server Version: 5.0.0`);
  
  server.close(() => {
    console.log('✅ HTTP server closed');
    process.exit(0);
  });

  setTimeout(() => {
    console.log('⚠️ Force closing server after 30 seconds');
    process.exit(1);
  }, 30000);
};

// Process signal handlers
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
  console.log('🎉 ================================================================');
  console.log('🚀 COTOG Backend Ready!');
  console.log('🎉 ================================================================');
  console.log('');
  console.log(`📡 Server URL: http://localhost:${PORT}`);
  console.log(`🌍 Environment: ${NODE_ENV}`);
  console.log(`🔗 Frontend URL: ${FRONTEND_URL}`);
  console.log(`💾 Memory Usage: ${Math.round(process.memoryUsage().heapUsed / 1024 / 1024)} MB`);
  console.log(`📋 Version: 5.0.0`);
  console.log('');
  console.log('🔧 Role System:');
  console.log('   👤 User Role: Join rooms, edit code, chat, voice');
  console.log('   👑 Room Creator: All user privileges + language control');
  console.log('');
  console.log('📋 Demo Accounts (All "user" role):');
  console.log('   👤 john.doe@example.com');
  console.log('   👤 sarah.wilson@example.com');
  console.log('   👤 alex.kim@example.com');
  console.log('   🔑 Password: password123');
  console.log('');
  console.log('🎙️ WebRTC Voice Chat Features:');
  console.log('   ✅ Enhanced P2P voice communication');
  console.log('   ✅ Connection conflict resolution');
  console.log('   ✅ Improved timing and error handling');
  console.log('   ✅ Comprehensive cleanup and recovery');
  console.log('');
  console.log('🏠 Room Management:');
  console.log('   👑 Room Creator: Can change coding language');
  console.log('   👤 Room Members: Can edit code, chat, and use voice');
  console.log('');
  console.log('📊 API Endpoints:');
  console.log('   POST /api/rooms/create - Create new room (authenticated users)');
  console.log('   GET /api/room/:roomId - Get room information');
  console.log('   POST /api/auth/login - User authentication');
  console.log('   POST /api/auth/signup - User registration (creates "user" role)');
  console.log('');
  console.log('✅ Server ready for collaborative coding!');
  console.log('🎯 Equal users with room creator language control!');
  console.log('⚡ Enhanced collaboration platform!');
  console.log('');
});

module.exports = { 
  app, 
  server, 
  io, 
  userService, 
  rooms, 
  roomsData, 
  voiceRooms,
  activePeers,
  webrtcConfig,
  iceServers
};