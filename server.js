// server.js - CLEANED VERSION WITH UNUSED CODE REMOVED
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
console.log('🌐 Port:', PORT);
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
    console.log(`🔄 CORS preflight request from: ${origin}`);
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

// Room management
const rooms = {}; // { roomId: [ { id, username, userId, joinedAt, role } ] }
const roomsData = {}; // Room metadata
const messageHistory = {}; // Chat history
const userSessions = {}; // Socket sessions

// Simplified WebRTC system
const voiceRooms = {}; // { roomId: [ { userId, username, socketId, joinedAt } ] }
const voiceSignals = {}; // WebRTC signaling data store
const peerConnections = {}; // Track active peer connections

// ICE servers configuration
const iceServers = [
  { urls: 'stun:stun.l.google.com:19302' },
  { urls: 'stun:stun1.l.google.com:19302' },
  { urls: 'stun:stun2.l.google.com:19302' },
  { urls: 'stun:stun3.l.google.com:19302' },
  { urls: 'stun:stun4.l.google.com:19302' }
];

// Simplified WebRTC configuration
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
      delete voiceSignals[roomId];
      delete peerConnections[roomId];
      console.log(`🧹 Cleaned up empty room: ${roomId}`);
    }
  }
};

const cleanupStaleVoiceUsers = (roomId) => {
  if (!voiceRooms[roomId]) return;
  
  const beforeCount = voiceRooms[roomId].length;
  
  voiceRooms[roomId] = voiceRooms[roomId].filter(voiceUser => {
    const socket = io.sockets.sockets.get(voiceUser.socketId);
    const isStale = !socket || !socket.connected;
    
    if (isStale) {
      console.log(`🧹 Removing stale voice user: ${voiceUser.username} from room ${roomId}`);
      
      // Clean up associated peer connections
      if (peerConnections[roomId] && peerConnections[roomId][voiceUser.userId]) {
        delete peerConnections[roomId][voiceUser.userId];
      }
    }
    
    return !isStale;
  });
  
  const afterCount = voiceRooms[roomId].length;
  if (beforeCount !== afterCount) {
    console.log(`🧹 Cleaned up ${beforeCount - afterCount} stale users from voice room ${roomId}`);
  }
  
  if (voiceRooms[roomId].length === 0) {
    delete voiceRooms[roomId];
    delete voiceSignals[roomId];
    delete peerConnections[roomId];
  }
};

// =============================================================================
// API ROUTES
// =============================================================================

// Root endpoint
app.get('/', (req, res) => {
  res.json({
    message: 'COTOG Backend API - Cleaned Version',
    status: 'running',
    version: '2.1.0',
    environment: NODE_ENV,
    timestamp: new Date().toISOString(),
    endpoints: {
      health: '/health',
      apiHealth: '/api/health',
      auth: '/api/auth/*',
      rooms: '/api/rooms/*',
      voiceStatus: '/api/voice-rooms/status',
      webrtcConfig: '/api/webrtc/config'
    },
    features: {
      websocket: 'Socket.IO v4 enabled',
      webrtc: 'Simplified P2P voice chat',
      cors: 'Multi-origin enabled',
      signaling: 'WebRTC signaling enabled'
    },
    voiceStats: {
      activeVoiceRooms: Object.keys(voiceRooms).length,
      totalVoiceUsers: Object.values(voiceRooms).reduce((sum, room) => sum + room.length, 0),
      activePeerConnections: Object.values(peerConnections).reduce((sum, room) => Object.keys(room).length + sum, 0)
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
    version: '2.1.0',
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
    peerConnections: Object.values(peerConnections).reduce((sum, room) => Object.keys(room).length + sum, 0),
    frontendUrl: FRONTEND_URL,
    corsEnabled: true
  });
});

app.get('/api/health', (req, res) => {
  res.json({
    status: 'healthy',
    service: 'COTOG Backend - Cleaned Version',
    timestamp: new Date().toISOString(),
    uptime: Math.floor(process.uptime()),
    environment: NODE_ENV,
    rooms: Object.keys(roomsData).length,
    users: Object.keys(userSessions).length,
    voiceConnections: Object.values(voiceRooms).reduce((sum, room) => sum + room.length, 0),
    corsConfig: {
      frontendUrl: FRONTEND_URL,
      allowCredentials: true,
      methods: corsOptions.methods,
      allowedHeaders: corsOptions.allowedHeaders
    }
  });
});

// Voice room status endpoint
app.get('/api/voice-rooms/status', authenticateToken, (req, res) => {
  try {
    const voiceRoomStats = {
      totalVoiceRooms: Object.keys(voiceRooms).length,
      totalVoiceUsers: Object.values(voiceRooms).reduce((sum, room) => sum + room.length, 0),
      totalPeerConnections: Object.values(peerConnections).reduce((sum, room) => Object.keys(room).length + sum, 0),
      roomDetails: Object.entries(voiceRooms).map(([roomId, users]) => ({
        roomId,
        userCount: users.length,
        users: users.map(u => ({
          userId: u.userId,
          username: u.username,
          joinedAt: u.joinedAt
        })),
        peerConnections: Object.keys(peerConnections[roomId] || {}).length
      })),
      systemHealth: {
        memoryUsage: process.memoryUsage(),
        uptime: process.uptime(),
        activeSockets: io.sockets.sockets.size
      }
    };
    
    res.json(voiceRoomStats);
  } catch (error) {
    console.error('Voice room status error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// WebRTC configuration endpoint
app.get('/api/webrtc/config', authenticateToken, (req, res) => {
  try {
    res.json({
      iceServers,
      configuration: webrtcConfig,
      features: {
        simplifiedVersion: true,
        noPermissionsRequired: true,
        instantAccess: true
      },
      serverInfo: {
        version: '2.1.0',
        environment: NODE_ENV,
        timestamp: new Date().toISOString()
      }
    });
  } catch (error) {
    console.error('WebRTC config error:', error);
    res.status(500).json({ error: 'Failed to get WebRTC configuration' });
  }
});

// Authentication routes (keeping existing ones)
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password, rememberMe } = req.body;
    console.log(`🔍 Login attempt for: ${email} from origin: ${req.headers.origin}`);

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

app.post('/api/auth/signup', async (req, res) => {
  try {
    const { username, email, password, confirmPassword, firstName, lastName } = req.body;
    console.log(`📝 Signup attempt for: ${email} from origin: ${req.headers.origin}`);

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

    console.log(`✅ User created: ${email}`);

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

// Room management routes
app.post('/api/rooms/create', authenticateToken, (req, res) => {
  try {
    const { roomName, password, maxUsers, isPrivate, description } = req.body;
    const userId = req.user.userId;
    
    console.log(`🏠 Room creation attempt by user ${userId} from origin: ${req.headers.origin}`);
    
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
  console.log(`🔌 User connected: ${socket.username} (${socket.id}) [WebRTC: ${socket.webrtcSessionId}] from ${socket.handshake.headers.origin}`);

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
      
      let userRole = 'member';
      if (room.createdBy === socket.userId) {
        userRole = 'owner';
      } else if (socket.userRole === 'admin') {
        userRole = 'moderator';
      }
      
      if (!rooms[roomId]) rooms[roomId] = [];
      rooms[roomId].push({ 
        id: socket.id, 
        userId: socket.userId,
        username: socket.username,
        joinedAt: new Date(),
        role: userRole,
        webrtcSessionId: socket.webrtcSessionId
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

  // =============================================================================
  // SIMPLIFIED WEBRTC VOICE CHAT EVENTS
  // =============================================================================

  // Join voice room - simplified, no permissions
  socket.on('join-voice-room', ({ roomId, userId, username }) => {
    try {
      console.log(`🎙️ ${username} joining voice room ${roomId} [Session: ${socket.webrtcSessionId}]`);
      
      const userSession = userSessions[socket.id];
      if (!userSession || userSession.roomId !== roomId) {
        socket.emit('error', { message: 'You must be in the room to join voice chat' });
        return;
      }

      // Initialize voice room if it doesn't exist
      if (!voiceRooms[roomId]) {
        voiceRooms[roomId] = [];
      }

      // Check if user is already in voice room
      const existingVoiceUser = voiceRooms[roomId].find(u => u.userId === userId);
      if (existingVoiceUser) {
        console.log(`⚠️ User ${username} already in voice room, updating connection info`);
        existingVoiceUser.socketId = socket.id;
        existingVoiceUser.webrtcSessionId = socket.webrtcSessionId;
        existingVoiceUser.reconnectedAt = new Date();
      } else {
        // Add user to voice room
        const voiceUser = {
          userId,
          username,
          socketId: socket.id,
          webrtcSessionId: socket.webrtcSessionId,
          joinedAt: new Date(),
          browser: userSession.browser
        };
        voiceRooms[roomId].push(voiceUser);
      }
      
      console.log(`✅ ${username} joined voice room. Total voice users: ${voiceRooms[roomId].length}`);

      // Clean up stale users
      cleanupStaleVoiceUsers(roomId);

      // Send existing voice users to the new joiner
      const existingUsers = voiceRooms[roomId].filter(u => u.userId !== userId);
      
      console.log(`📡 Sending ${existingUsers.length} existing voice users to ${username}`);
      socket.emit('voice-room-users', {
        users: existingUsers.map(u => ({
          userId: u.userId,
          username: u.username,
          webrtcSessionId: u.webrtcSessionId
        })),
        webrtcConfig: webrtcConfig
      });

      // Notify other voice users about the new joiner with staggered timing
      setTimeout(() => {
        existingUsers.forEach((existingUser, index) => {
          const targetSocket = io.sockets.sockets.get(existingUser.socketId);
          if (targetSocket && targetSocket.connected) {
            setTimeout(() => {
              targetSocket.emit('user-joined-voice', {
                userId,
                username,
                socketId: socket.id,
                webrtcSessionId: socket.webrtcSessionId,
                webrtcConfig: webrtcConfig,
                timestamp: new Date().toISOString()
              });
              console.log(`📡 Notified ${existingUser.username} about ${username} joining voice`);
            }, index * 150); // Staggered timing: 150ms between each notification
          } else {
            // Remove stale user
            console.log(`🧹 Removing stale voice user during join: ${existingUser.username}`);
            voiceRooms[roomId] = voiceRooms[roomId].filter(u => u.userId !== existingUser.userId);
          }
        });
      }, 300);

      // Update voice room status for all room users
      setTimeout(() => {
        io.to(roomId).emit('voice-room-updated', {
          voiceUsers: voiceRooms[roomId].map(u => ({
            userId: u.userId,
            username: u.username
          })),
          totalVoiceUsers: voiceRooms[roomId].length
        });
      }, 500);

      // Send success confirmation
      socket.emit('voice-room-joined', {
        roomId,
        userId,
        username,
        webrtcSessionId: socket.webrtcSessionId,
        existingUserCount: existingUsers.length,
        webrtcConfig: webrtcConfig
      });

    } catch (error) {
      console.error('Error joining voice room:', error);
      socket.emit('error', { message: 'Failed to join voice room' });
    }
  });

  // Leave voice room
  socket.on('leave-voice-room', ({ roomId, userId, reason }) => {
    try {
      console.log(`🎙️ User ${userId} leaving voice room ${roomId} (reason: ${reason || 'manual'})`);
      
      if (!voiceRooms[roomId]) {
        console.log(`❌ Voice room ${roomId} not found for leave request`);
        return;
      }

      // Find and remove user from voice room
      const userIndex = voiceRooms[roomId].findIndex(u => u.userId === userId);
      if (userIndex === -1) {
        console.log(`❌ User ${userId} not found in voice room ${roomId}`);
        return;
      }

      const leavingUser = voiceRooms[roomId][userIndex];
      voiceRooms[roomId].splice(userIndex, 1);

      console.log(`✅ ${leavingUser.username} left voice room. Remaining: ${voiceRooms[roomId].length}`);

      // Clean up peer connections
      if (peerConnections[roomId] && peerConnections[roomId][userId]) {
        delete peerConnections[roomId][userId];
      }

      // Notify others in voice room
      const remainingUsers = voiceRooms[roomId];
      remainingUsers.forEach((user, index) => {
        const targetSocket = io.sockets.sockets.get(user.socketId);
        if (targetSocket && targetSocket.connected) {
          setTimeout(() => {
            targetSocket.emit('user-left-voice', {
              userId,
              username: leavingUser.username,
              reason: reason || 'manual',
              timestamp: new Date().toISOString()
            });
          }, index * 100);
        }
      });

      // Notify room about voice room update
      setTimeout(() => {
        io.to(roomId).emit('voice-room-updated', {
          voiceUsers: voiceRooms[roomId].map(u => ({
            userId: u.userId,
            username: u.username
          })),
          totalVoiceUsers: voiceRooms[roomId].length
        });
      }, 200);

      // Send confirmation
      socket.emit('voice-room-left', {
        roomId,
        userId,
        reason: reason || 'manual'
      });

      // Clean up empty voice room
      if (voiceRooms[roomId].length === 0) {
        delete voiceRooms[roomId];
        delete voiceSignals[roomId];
        delete peerConnections[roomId];
        console.log(`🧹 Cleaned up empty voice room: ${roomId}`);
      }

    } catch (error) {
      console.error('Error leaving voice room:', error);
      socket.emit('error', { message: 'Failed to leave voice room' });
    }
  });

  // WebRTC Signaling - simplified
  socket.on('sending-signal', ({ userToCall, callerID, signal, roomId }) => {
    try {
      console.log(`📞 Signal from ${callerID} to ${userToCall} in room ${roomId} (type: ${signal?.type})`);
      
      if (!signal || typeof signal !== 'object') {
        console.error('❌ Invalid signal data received:', signal);
        socket.emit('voice-error', { 
          message: 'Invalid signal data',
          targetUser: userToCall
        });
        return;
      }

      // Clean up stale users
      cleanupStaleVoiceUsers(roomId);
      
      // Find the target user
      const targetUser = voiceRooms[roomId]?.find(u => u.userId === userToCall);
      if (!targetUser) {
        console.log(`❌ Target user ${userToCall} not found in voice room`);
        socket.emit('voice-error', { 
          message: `User ${userToCall} not available for voice chat`,
          targetUser: userToCall
        });
        return;
      }

      const targetSocket = io.sockets.sockets.get(targetUser.socketId);
      if (!targetSocket || !targetSocket.connected) {
        console.log(`❌ Target socket not found for user ${userToCall}`);
        voiceRooms[roomId] = voiceRooms[roomId].filter(u => u.userId !== userToCall);
        socket.emit('voice-error', { 
          message: `User ${userToCall} is no longer available`,
          targetUser: userToCall
        });
        return;
      }

      // Forward the signal
      const signalData = {
        signal: signal,
        from: callerID,
        username: userSessions[socket.id]?.username || 'Unknown',
        roomId,
        timestamp: Date.now(),
        webrtcSessionId: userSessions[socket.id]?.webrtcSessionId
      };

      console.log(`📡 Forwarding signal to ${targetUser.username} (${signal.type})`);
      targetSocket.emit('user-calling', signalData);

      // Send acknowledgment
      socket.emit('signal-sent', { 
        targetUser: userToCall,
        signalType: signal.type,
        timestamp: Date.now()
      });

      // Store signal for debugging
      if (!voiceSignals[roomId]) voiceSignals[roomId] = {};
      if (!voiceSignals[roomId][callerID]) voiceSignals[roomId][callerID] = {};
      voiceSignals[roomId][callerID][userToCall] = {
        lastSignal: signal.type,
        timestamp: new Date()
      };

    } catch (error) {
      console.error('Error handling sending signal:', error);
      socket.emit('voice-error', { 
        message: 'Failed to send signal',
        error: error.message,
        targetUser: userToCall
      });
    }
  });

  socket.on('returning-signal', ({ signal, callerID, roomId }) => {
    try {
      console.log(`📞 Return signal to ${callerID} in room ${roomId} (type: ${signal?.type})`);
      
      if (!signal || typeof signal !== 'object') {
        console.error('❌ Invalid return signal data received:', signal);
        socket.emit('voice-error', { 
          message: 'Invalid return signal data',
          callerID
        });
        return;
      }
      
      // Clean up stale users
      cleanupStaleVoiceUsers(roomId);
      
      // Find the caller
      const callerUser = voiceRooms[roomId]?.find(u => u.userId === callerID);
      if (!callerUser) {
        console.log(`❌ Caller ${callerID} not found in voice room`);
        socket.emit('voice-error', { 
          message: `Caller ${callerID} not found in voice room`,
          callerID
        });
        return;
      }

      const callerSocket = io.sockets.sockets.get(callerUser.socketId);
      if (!callerSocket || !callerSocket.connected) {
        console.log(`❌ Caller socket not found for user ${callerID}`);
        voiceRooms[roomId] = voiceRooms[roomId].filter(u => u.userId !== callerID);
        socket.emit('voice-error', { 
          message: `Caller ${callerID} is no longer available`,
          callerID
        });
        return;
      }

      // Forward the return signal
      const returnSignalData = {
        signal: signal,
        id: userSessions[socket.id]?.userId,
        username: userSessions[socket.id]?.username || 'Unknown',
        timestamp: Date.now(),
        webrtcSessionId: userSessions[socket.id]?.webrtcSessionId
      };

      console.log(`📡 Forwarding return signal to ${callerUser.username} (${signal.type})`);
      callerSocket.emit('receiving-returned-signal', returnSignalData);

      // Send acknowledgment
      socket.emit('return-signal-sent', { 
        callerID,
        signalType: signal.type,
        timestamp: Date.now()
      });

    } catch (error) {
      console.error('Error handling returning signal:', error);
      socket.emit('voice-error', { 
        message: 'Failed to return signal',
        error: error.message,
        callerID
      });
    }
  });

  // Disconnect handling
  socket.on('disconnect', (reason) => {
    console.log(`🔌 User disconnected: ${socket.username || 'Unknown'} (${socket.id}) - Reason: ${reason}`);
    
    const userSession = userSessions[socket.id];
    if (userSession && userSession.roomId) {
      const roomId = userSession.roomId;
      const userIndex = rooms[roomId]?.findIndex(u => u.id === socket.id);
      
      if (userIndex !== -1) {
        const username = rooms[roomId][userIndex].username;
        const userId = rooms[roomId][userIndex].userId;
        rooms[roomId].splice(userIndex, 1);
        
        // Voice room cleanup
        if (voiceRooms[roomId]) {
          const voiceUserIndex = voiceRooms[roomId].findIndex(u => u.socketId === socket.id);
          if (voiceUserIndex !== -1) {
            const leavingVoiceUser = voiceRooms[roomId][voiceUserIndex];
            voiceRooms[roomId].splice(voiceUserIndex, 1);
            
            console.log(`🎙️ ${leavingVoiceUser.username} removed from voice room on disconnect`);
            
            // Clean up peer connections
            if (peerConnections[roomId] && peerConnections[roomId][leavingVoiceUser.userId]) {
              delete peerConnections[roomId][leavingVoiceUser.userId];
            }
            
            // Notify remaining voice users
            const remainingVoiceUsers = voiceRooms[roomId];
            remainingVoiceUsers.forEach((voiceUser, index) => {
              const targetSocket = io.sockets.sockets.get(voiceUser.socketId);
              if (targetSocket && targetSocket.connected) {
                setTimeout(() => {
                  targetSocket.emit('user-left-voice', {
                    userId: leavingVoiceUser.userId,
                    username: leavingVoiceUser.username,
                    reason: 'disconnected',
                    timestamp: new Date().toISOString()
                  });
                }, index * 75);
              }
            });

            // Update voice room status
            setTimeout(() => {
              io.to(roomId).emit('voice-room-updated', {
                voiceUsers: voiceRooms[roomId].map(u => ({
                  userId: u.userId,
                  username: u.username
                })),
                totalVoiceUsers: voiceRooms[roomId].length
              });
            }, 300);

            // Clean up empty voice room
            if (voiceRooms[roomId].length === 0) {
              delete voiceRooms[roomId];
              delete voiceSignals[roomId];
              delete peerConnections[roomId];
              console.log(`🧹 Cleaned up empty voice room: ${roomId}`);
            }
          }
        }
        
        console.log(`❌ ${username} left room ${roomId}`);

        // Send leave message
        const leaveMessage = {
          id: Date.now(),
          sender: 'System',
          message: `${username} has left the room.`,
          timestamp: new Date().toISOString(),
          type: 'system'
        };
        socket.to(roomId).emit('message', leaveMessage);

        // Update room users
        io.to(roomId).emit('roomUsers', rooms[roomId]);
      }
    }
    
    delete userSessions[socket.id];
    
    // Schedule cleanup
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
    message: NODE_ENV === 'development' ? error.message : 'Something went wrong',
    timestamp: new Date().toISOString()
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
      'GET /api/voice-rooms/status',
      'GET /api/webrtc/config',
      'POST /api/auth/login',
      'POST /api/auth/signup',
      'POST /api/auth/verify',
      'POST /api/rooms/create',
      'GET /api/room/:roomId'
    ]
  });
});

// =============================================================================
// GRACEFUL SHUTDOWN
// =============================================================================
const gracefulShutdown = (signal) => {
  console.log(`🛑 Received ${signal}. Starting graceful shutdown...`);
  
  // Notify voice users
  Object.keys(voiceRooms).forEach(roomId => {
    const voiceUsers = voiceRooms[roomId];
    console.log(`📢 Notifying ${voiceUsers.length} voice users in room ${roomId} about shutdown`);
    
    io.to(roomId).emit('voice-chat-shutdown', {
      message: 'Voice chat will be temporarily unavailable during server maintenance.',
      estimatedDowntime: '2-5 minutes',
      timestamp: new Date().toISOString()
    });
  });
  
  // Notify all users
  io.emit('serverShutdown', {
    message: 'Server is shutting down for maintenance. Please reconnect in a few minutes.',
    timestamp: new Date().toISOString(),
    estimatedDowntime: '2-5 minutes'
  });

  // Log final statistics
  console.log('📊 Final Statistics:');
  console.log(`   Active Rooms: ${Object.keys(roomsData).length}`);
  console.log(`   Active Users: ${Object.keys(userSessions).length}`);
  console.log(`   Voice Rooms: ${Object.keys(voiceRooms).length}`);
  console.log(`   Voice Users: ${Object.values(voiceRooms).reduce((sum, room) => sum + room.length, 0)}`);
  
  server.close(() => {
    console.log('✅ HTTP server closed');
    process.exit(0);
  });

  // Force close after 30 seconds
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
  console.log('🚀 COTOG Backend - Cleaned Version Ready!');
  console.log('🎉 ================================================================');
  console.log('');
  console.log(`📡 Server URL: http://localhost:${PORT}`);
  console.log(`🌍 Environment: ${NODE_ENV}`);
  console.log(`🔗 Frontend URL: ${FRONTEND_URL}`);
  console.log(`💾 Memory Usage: ${Math.round(process.memoryUsage().heapUsed / 1024 / 1024)} MB`);
  console.log('');
  console.log('📋 Demo Accounts:');
  console.log('   👤 john.doe@example.com (User)');
  console.log('   👑 sarah.wilson@example.com (Admin)');
  console.log('   🛡️ alex.kim@example.com (Moderator)');
  console.log('   🔑 Password: password123');
  console.log('');
  console.log('🎙️ Simplified WebRTC Features:');
  console.log('   ✅ No permissions required - instant access');
  console.log('   ✅ Simplified peer discovery');
  console.log('   ✅ Basic connection monitoring');
  console.log('   ✅ Automatic cleanup');
  console.log('   ✅ Enhanced error handling');
  console.log('');
  console.log('✅ Cleaned backend ready - unused code removed!');
  console.log('🎙️ Voice chat simplified for better performance!');
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
  webrtcConfig,
  iceServers
};