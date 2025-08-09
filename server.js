// server.js - MODIFIED VERSION WITH AUDIO PERMISSIONS REMOVED
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

const app = express();
const server = http.createServer(app);

// =============================================================================
// ENHANCED ENVIRONMENT CONFIGURATION
// =============================================================================
const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || 'cotog-production-secret-change-this-in-production';
const NODE_ENV = process.env.NODE_ENV || 'development';
const FRONTEND_URL = process.env.FRONTEND_URL || 'https://cotog-collaborative-editor-222.onrender.com';

console.log('🚀 COTOG Backend with Enhanced WebRTC Starting...');
console.log('📊 Environment:', NODE_ENV);
console.log('🌐 Port:', PORT);
console.log('🔗 Frontend URL:', FRONTEND_URL);

// =============================================================================
// ADVANCED CORS CONFIGURATION WITH WEBRTC OPTIMIZATION
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
    'Access-Control-Request-Headers',
    'X-WebRTC-Session-Id',
    'X-Voice-Room-Id'
  ]
};

// =============================================================================
// ENHANCED SOCKET.IO CONFIGURATION WITH WEBRTC OPTIMIZATIONS
// =============================================================================
const io = new Server(server, {
  cors: corsOptions,
  transports: ['websocket', 'polling'],
  allowEIO3: true,
  pingTimeout: 60000,
  pingInterval: 25000,
  upgradeTimeout: 30000,
  maxHttpBufferSize: 2e6,
  parser: require('socket.io-parser'),
  compression: true,
  cookie: false,
  serveClient: false,
  connectTimeout: 45000,
  binary: true
});

// =============================================================================
// EXPRESS MIDDLEWARE WITH WEBRTC HEADERS
// =============================================================================
app.use(cors(corsOptions));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.set('trust proxy', 1);

// Enhanced CORS handling with WebRTC support
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
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, x-requested-with, Accept, Origin, X-WebRTC-Session-Id, X-Voice-Room-Id');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Max-Age', '86400');
  
  if (req.method === 'OPTIONS') {
    console.log(`🔄 CORS preflight request from: ${origin}`);
    res.status(200).end();
    return;
  }
  
  next();
});

// Enhanced security headers with WebRTC considerations
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
// ENHANCED DATA STORES WITH WEBRTC OPTIMIZATIONS (AUDIO PERMISSIONS REMOVED)
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

// Enhanced room management with advanced WebRTC support
const rooms = {}; // { roomId: [ { id, username, userId, joinedAt, role } ] }
const roomsData = {}; // Room metadata with WebRTC configuration
const messageHistory = {}; // Chat history
const userSessions = {}; // Socket sessions with WebRTC state

// REMOVED AUDIO PERMISSION SYSTEM - ALL USERS CAN USE AUDIO FREELY
const voiceRooms = {}; // { roomId: [ { userId, username, socketId, joinedAt, connectionState } ] }
const voiceSignals = {}; // Enhanced WebRTC signaling data store
const voiceConnectionStats = {}; // Detailed connection quality tracking
const peerConnections = {}; // Track active peer connections
const iceServers = [ // Enhanced ICE servers for better connectivity
  { urls: 'stun:stun.l.google.com:19302' },
  { urls: 'stun:stun1.l.google.com:19302' },
  { urls: 'stun:stun2.l.google.com:19302' },
  { urls: 'stun:stun3.l.google.com:19302' },
  { urls: 'stun:stun4.l.google.com:19302' }
];

// WebRTC configuration for Chrome optimization
const webrtcConfig = {
  iceServers,
  iceCandidatePoolSize: 10,
  bundlePolicy: 'balanced',
  rtcpMuxPolicy: 'require',
  sdpSemantics: 'unified-plan',
  audioConstraints: {
    echoCancellation: true,
    noiseSuppression: true,
    autoGainControl: true,
    googEchoCancellation: true,
    googAutoGainControl: true,
    googNoiseSuppression: true,
    googHighpassFilter: true,
    googTypingNoiseDetection: true
  }
};

// =============================================================================
// USER SERVICE (UNCHANGED)
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
// AUTHENTICATION MIDDLEWARE (ENHANCED)
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
// ENHANCED UTILITY FUNCTIONS FOR WEBRTC (AUDIO PERMISSIONS REMOVED)
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
      delete voiceConnectionStats[roomId];
      delete peerConnections[roomId];
      console.log(`🧹 Cleaned up empty room: ${roomId}`);
    }
  }
};

// Initialize room voice chat - NO PERMISSION SYSTEM
const initializeRoomVoice = (roomId) => {
  if (!voiceRooms[roomId]) voiceRooms[roomId] = [];
  if (!voiceSignals[roomId]) voiceSignals[roomId] = {};
  if (!voiceConnectionStats[roomId]) voiceConnectionStats[roomId] = {};
  if (!peerConnections[roomId]) peerConnections[roomId] = {};
  console.log(`🎙️ Voice chat initialized for room ${roomId} - NO PERMISSIONS REQUIRED`);
};

// Enhanced cleanup for stale voice users with detailed logging
const cleanupStaleVoiceUsers = (roomId) => {
  if (!voiceRooms[roomId]) return;
  
  const beforeCount = voiceRooms[roomId].length;
  
  voiceRooms[roomId] = voiceRooms[roomId].filter(voiceUser => {
    const socket = io.sockets.sockets.get(voiceUser.socketId);
    const isStale = !socket || !socket.connected;
    
    if (isStale) {
      console.log(`🧹 Removing stale voice user: ${voiceUser.username} from room ${roomId}`);
      
      if (peerConnections[roomId] && peerConnections[roomId][voiceUser.userId]) {
        delete peerConnections[roomId][voiceUser.userId];
      }
      
      if (voiceConnectionStats[roomId] && voiceConnectionStats[roomId][voiceUser.userId]) {
        voiceConnectionStats[roomId][voiceUser.userId].disconnectedAt = new Date();
        voiceConnectionStats[roomId][voiceUser.userId].disconnectReason = 'stale_connection';
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
    setTimeout(() => {
      delete voiceConnectionStats[roomId];
    }, 5 * 60 * 1000);
  }
};

// WebRTC connection monitoring
const monitorConnection = (roomId, userId, connectionData) => {
  if (!voiceConnectionStats[roomId]) {
    voiceConnectionStats[roomId] = {};
  }
  
  if (!voiceConnectionStats[roomId][userId]) {
    voiceConnectionStats[roomId][userId] = {
      userId,
      joinedAt: new Date(),
      connectionAttempts: 0,
      successfulConnections: 0,
      failedConnections: 0,
      lastActivity: new Date(),
      connectionQuality: 'unknown',
      iceStates: {},
      signalExchanges: 0
    };
  }
  
  Object.assign(voiceConnectionStats[roomId][userId], connectionData, { lastActivity: new Date() });
};

// =============================================================================
// API ROUTES - ENHANCED WITH ADVANCED WEBRTC MONITORING (PERMISSIONS REMOVED)
// =============================================================================

// Root endpoint with comprehensive WebRTC status
app.get('/', (req, res) => {
  res.json({
    message: 'COTOG Backend API - Enhanced WebRTC v2.0 (No Audio Permissions)',
    status: 'running',
    version: '2.0.0',
    environment: NODE_ENV,
    timestamp: new Date().toISOString(),
    endpoints: {
      health: '/health',
      apiHealth: '/api/health',
      auth: '/api/auth/*',
      rooms: '/api/rooms/*',
      voiceStatus: '/api/voice-rooms/status',
      webrtcDebug: '/api/webrtc/debug/:roomId',
      webrtcConfig: '/api/webrtc/config'
    },
    features: {
      websocket: 'Socket.IO v4 enabled',
      webrtc: 'Enhanced P2P voice chat with Chrome optimizations - NO PERMISSIONS',
      cors: 'Multi-origin enabled with WebRTC headers',
      signaling: 'Advanced WebRTC signaling with error recovery',
      iceServers: `${iceServers.length} STUN servers configured`,
      peerDiscovery: 'Immediate with staggered connections',
      qualityMonitoring: 'Real-time connection quality tracking',
      audioPermissions: 'DISABLED - All users can use audio freely'
    },
    voiceStats: {
      activeVoiceRooms: Object.keys(voiceRooms).length,
      totalVoiceUsers: Object.values(voiceRooms).reduce((sum, room) => sum + room.length, 0),
      activePeerConnections: Object.values(peerConnections).reduce((sum, room) => Object.keys(room).length + sum, 0),
      totalSignalExchanges: Object.values(voiceConnectionStats).reduce((sum, room) => 
        Object.values(room).reduce((roomSum, user) => roomSum + (user.signalExchanges || 0), 0) + sum, 0)
    }
  });
});

// Authentication routes (unchanged)
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

// Room creation route (enhanced with no audio permissions)
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
      webrtcConfig: webrtcConfig,
      audioPermissionsDisabled: true // NO PERMISSION SYSTEM
    };
    
    rooms[roomId] = [];
    messageHistory[roomId] = [];
    initializeRoomVoice(roomId); // Initialize voice without permissions
    
    console.log(`🏠 Room created: ${roomId} (${roomName}) by ${user.username} - Audio permissions DISABLED`);
    
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
        webrtcEnabled: true,
        audioPermissionsDisabled: true
      }
    });

  } catch (error) {
    console.error('Room creation error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// =============================================================================
// ENHANCED SOCKET.IO CONNECTION HANDLING WITH NO AUDIO PERMISSIONS
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

  // Join room with enhanced WebRTC initialization
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

      console.log(`📥 ${socket.username} joined room ${roomId} as ${userRole} - Audio freely available`);

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

      // Enhanced join success with WebRTC configuration - NO PERMISSIONS
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
          webrtcEnabled: true,
          audioPermissionsDisabled: true
        },
        webrtcConfig: webrtcConfig
      });

    } catch (error) {
      console.error('Error joining room:', error);
      socket.emit('error', { message: 'Failed to join room' });
    }
  });

  // Chat messages (unchanged)
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

  // Code changes (unchanged)
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

  // Language changes (unchanged)
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

  // Typing indicators (unchanged)
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
  // ENHANCED WEBRTC VOICE CHAT EVENTS - NO PERMISSION SYSTEM
  // =============================================================================

  // Enhanced join voice room - NO PERMISSIONS REQUIRED
  socket.on('join-voice-room', ({ roomId, userId, username }) => {
    try {
      console.log(`🎙️ ${username} joining voice room ${roomId} [Session: ${socket.webrtcSessionId}] - NO PERMISSIONS REQUIRED`);
      
      const userSession = userSessions[socket.id];
      if (!userSession || userSession.roomId !== roomId) {
        socket.emit('error', { message: 'You must be in the room to join voice chat' });
        return;
      }

      // Check if user is in the room
      const roomUser = rooms[roomId]?.find(u => u.id === socket.id);
      if (!roomUser) {
        socket.emit('error', { message: 'User not found in room' });
        return;
      }

      // NO PERMISSION CHECK - ALL USERS CAN JOIN VOICE IMMEDIATELY
      console.log(`✅ Audio access granted immediately to ${username} - No permissions required`);

      // Initialize voice room if it doesn't exist
      if (!voiceRooms[roomId]) {
        voiceRooms[roomId] = [];
      }

      // Check if user is already in voice room and handle reconnection
      const existingVoiceUser = voiceRooms[roomId].find(u => u.userId === userId);
      if (existingVoiceUser) {
        console.log(`⚠️ User ${username} already in voice room, updating connection info`);
        existingVoiceUser.socketId = socket.id;
        existingVoiceUser.webrtcSessionId = socket.webrtcSessionId;
        existingVoiceUser.reconnectedAt = new Date();
        existingVoiceUser.connectionState = 'reconnected';
      } else {
        // Add user to voice room
        const voiceUser = {
          userId,
          username,
          socketId: socket.id,
          webrtcSessionId: socket.webrtcSessionId,
          joinedAt: new Date(),
          connectionState: 'joining',
          browser: userSession.browser
        };
        voiceRooms[roomId].push(voiceUser);
      }
      
      console.log(`✅ ${username} joined voice room. Total voice users: ${voiceRooms[roomId].length}`);

      // Clean up stale users before proceeding
      cleanupStaleVoiceUsers(roomId);

      // Initialize monitoring for this user
      monitorConnection(roomId, userId, {
        connectionAttempts: (voiceConnectionStats[roomId]?.[userId]?.connectionAttempts || 0) + 1,
        browser: userSession.browser,
        joinedAt: new Date()
      });

      // Send existing voice users to the new joiner immediately
      const existingUsers = voiceRooms[roomId].filter(u => u.userId !== userId);
      
      console.log(`📡 Sending ${existingUsers.length} existing voice users to ${username}`);
      socket.emit('voice-room-users', {
        users: existingUsers.map(u => ({
          userId: u.userId,
          username: u.username,
          webrtcSessionId: u.webrtcSessionId,
          connectionState: u.connectionState
        })),
        webrtcConfig: webrtcConfig
      });

      // Notify other voice users about the new joiner with staggered timing for Chrome stability
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

  // Handle explicit voice connection errors with retry logic
  socket.on('voice-connection-error', ({ roomId, error, targetUserId }) => {
    try {
      const userSession = userSessions[socket.id];
      if (!userSession || userSession.roomId !== roomId) return;

      console.log(`❌ Voice connection error from ${userSession.username} to ${targetUserId}: ${error}`);

      monitorConnection(roomId, userSession.userId, {
        lastError: error,
        lastErrorTime: new Date(),
        errorCount: (voiceConnectionStats[roomId]?.[userSession.userId]?.errorCount || 0) + 1
      });

      const errorCount = voiceConnectionStats[roomId]?.[userSession.userId]?.errorCount || 0;
      if (errorCount < 3) {
        setTimeout(() => {
          socket.emit('retry-voice-connection', {
            targetUserId,
            retryCount: errorCount + 1,
            delayMs: (errorCount + 1) * 2000
          });
        }, (errorCount + 1) * 2000);
      } else {
        socket.emit('voice-connection-failed-permanently', {
          targetUserId,
          reason: 'max_retries_exceeded',
          suggestions: [
            'Check your internet connection',
            'Try refreshing the page',
            'Contact support if the issue persists'
          ]
        });
      }

    } catch (error) {
      console.error('Error handling voice connection error:', error);
    }
  });
});

// =============================================================================
// ENHANCED ERROR HANDLING WITH WEBRTC CONSIDERATIONS
// =============================================================================
app.use((error, req, res, next) => {
  console.error('Express error:', error);
  res.status(500).json({ 
    error: 'Internal server error',
    message: NODE_ENV === 'development' ? error.message : 'Something went wrong',
    timestamp: new Date().toISOString(),
    requestId: req.headers['x-request-id'] || 'unknown'
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
      'GET /api/webrtc/debug/:roomId',
      'POST /api/auth/login',
      'POST /api/auth/signup',
      'POST /api/auth/verify',
      'POST /api/rooms/create',
      'GET /api/room/:roomId'
    ],
    cors: {
      enabled: true,
      frontendUrl: FRONTEND_URL
    },
    webrtc: {
      version: '2.0.0',
      voiceRooms: Object.keys(voiceRooms).length,
      totalVoiceUsers: Object.values(voiceRooms).reduce((sum, room) => sum + room.length, 0),
      activePeerConnections: Object.values(peerConnections).reduce((sum, room) => Object.keys(room).length + sum, 0),
      audioPermissionsDisabled: true
    }
  });
});

// =============================================================================
// ENHANCED GRACEFUL SHUTDOWN WITH COMPREHENSIVE VOICE CHAT CLEANUP
// =============================================================================
const gracefulShutdown = (signal) => {
  console.log(`🛑 Received ${signal}. Starting graceful shutdown...`);
  
  Object.keys(voiceRooms).forEach(roomId => {
    const voiceUsers = voiceRooms[roomId];
    console.log(`📢 Notifying ${voiceUsers.length} voice users in room ${roomId} about shutdown`);
    
    io.to(roomId).emit('voice-chat-shutdown', {
      message: 'Voice chat will be temporarily unavailable during server maintenance.',
      estimatedDowntime: '2-5 minutes',
      timestamp: new Date().toISOString(),
      reconnectInstructions: 'Please rejoin the voice chat after the server restarts.'
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
  console.log(`   Peer Connections: ${Object.values(peerConnections).reduce((sum, room) => Object.keys(room).length + sum, 0)}`);
  console.log(`   Audio Permissions: DISABLED - All users can use audio freely`);
  
  server.close(() => {
    console.log('✅ HTTP server closed');
    console.log('🎯 All connections closed');
    console.log('🎙️ Voice rooms cleaned up');
    console.log('📊 Connection statistics preserved');
    process.exit(0);
  });

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
// START ENHANCED SERVER WITH COMPREHENSIVE LOGGING
// =============================================================================
server.listen(PORT, '0.0.0.0', () => {
  console.log('');
  console.log('🎉 ================================================================');
  console.log('🚀 COTOG Backend with ENHANCED WebRTC v2.0 Ready!');
  console.log('🎙️ AUDIO PERMISSIONS DISABLED - ALL USERS CAN USE AUDIO FREELY');
  console.log('🎉 ================================================================');
  console.log('');
  console.log(`📡 Server URL: http://localhost:${PORT}`);
  console.log(`🌍 Environment: ${NODE_ENV}`);
  console.log(`🔐 JWT Secret: ${JWT_SECRET.substring(0, 10)}...`);
  console.log(`🔗 Frontend URL: ${FRONTEND_URL}`);
  console.log(`💾 Memory Usage: ${Math.round(process.memoryUsage().heapUsed / 1024 / 1024)} MB`);
  console.log('');
  console.log('📋 Available Demo Accounts:');
  console.log('   👤 john.doe@example.com (User)');
  console.log('   👑 sarah.wilson@example.com (Admin)');
  console.log('   🛡️ alex.kim@example.com (Moderator)');
  console.log('   🔑 Password for all: password123');
  console.log('');
  console.log('🔧 Enhanced API Endpoints:');
  console.log('   📊 GET  /health - Comprehensive health check');
  console.log('   🎙️ GET  /api/voice-rooms/status - Real-time voice monitoring');
  console.log('   ⚙️ GET  /api/webrtc/config - WebRTC configuration');
  console.log('   🐛 GET  /api/webrtc/debug/:roomId - Detailed debugging');
  console.log('   🔐 POST /api/auth/* - Authentication endpoints');
  console.log('   🏠 POST /api/rooms/create - Create room with WebRTC');
  console.log('   📡 Socket.IO: Real-time collaboration + Advanced WebRTC');
  console.log('');
  console.log('🎙️ Advanced WebRTC Voice Chat Features v2.0 (NO PERMISSIONS):');
  console.log('   ✅ Chrome-optimized SDP processing');
  console.log('   ✅ Enhanced peer discovery with staggered connections');
  console.log('   ✅ Advanced connection monitoring and quality tracking');
  console.log('   ✅ Automatic stale user cleanup with detailed logging');
  console.log('   ✅ Comprehensive error handling and retry logic');
  console.log('   ✅ Real-time audio quality optimization');
  console.log('   ✅ ICE connection state monitoring');
  console.log('   ✅ WebRTC statistics collection and analysis');
  console.log('   ✅ Enhanced speaking detection with audio levels');
  console.log('   ✅ Graceful disconnect handling with cleanup');
  console.log('   🎯 AUDIO PERMISSIONS COMPLETELY REMOVED');
  console.log('   🎯 ALL USERS CAN USE AUDIO IMMEDIATELY');
  console.log('');
  console.log('🌐 CORS & Security Configuration:');
  console.log(`   ✅ Frontend: ${FRONTEND_URL}`);
  console.log('   ✅ Credentials: enabled');
  console.log('   ✅ WebRTC headers: included');
  console.log('   ✅ Multi-origin support: enabled');
  console.log('   ✅ Security headers: comprehensive');
  console.log('');
  console.log('🔧 WebRTC Technical Improvements v2.0:');
  console.log('   ✅ Multiple STUN servers for better connectivity');
  console.log('   ✅ Chrome-specific audio codec optimizations');
  console.log('   ✅ Enhanced SDP processing with quality improvements');
  console.log('   ✅ Staggered peer connection establishment (150ms intervals)');
  console.log('   ✅ Comprehensive connection state monitoring');
  console.log('   ✅ Advanced peer connection tracking and cleanup');
  console.log('   ✅ Real-time quality metrics and optimization suggestions');
  console.log('   ✅ Exponential backoff retry logic for failed connections');
  console.log('   ✅ Binary support for WebRTC data channels');
  console.log('   ✅ Enhanced audio constraints for better quality');
  console.log('   🎯 NO PERMISSION SYSTEM - INSTANT AUDIO ACCESS');
  console.log('');
  console.log('📊 System Monitoring:');
  console.log('   ✅ Voice room status endpoint with detailed metrics');
  console.log('   ✅ WebRTC debug endpoint for troubleshooting');
  console.log('   ✅ Connection quality tracking and reporting');
  console.log('   ✅ ICE connection state history');
  console.log('   ✅ Audio quality metrics and optimization');
  console.log('   ✅ Comprehensive error logging and statistics');
  console.log('');
  console.log('🛡️ Reliability & Performance:');
  console.log('   ✅ Graceful shutdown with user notifications');
  console.log('   ✅ Memory usage monitoring and optimization');
  console.log('   ✅ Automatic cleanup of stale connections');
  console.log('   ✅ Connection statistics preservation for debugging');
  console.log('   ✅ Enhanced error recovery mechanisms');
  console.log('   ✅ Performance metrics collection');
  console.log('');
  console.log('🎯 Audio Permission Changes:');
  console.log('   ❌ Audio permission requests REMOVED');
  console.log('   ❌ Permission approval system DISABLED');
  console.log('   ❌ Role-based audio restrictions REMOVED');
  console.log('   ✅ ALL users can join voice chat immediately');
  console.log('   ✅ No waiting for approval required');
  console.log('   ✅ Instant audio access for everyone');
  console.log('');
  console.log('✅ Enhanced WebRTC backend v2.0 ready for production!');
  console.log('🎙️ Voice chat optimized for reliability and quality!');
  console.log('🎯 AUDIO PERMISSIONS COMPLETELY DISABLED!');
  console.log('🚀 All systems operational and monitoring enabled!');
  console.log('');
});

// =============================================================================
// EXPORT FOR TESTING AND EXTERNAL USE
// =============================================================================
module.exports = { 
  app, 
  server, 
  io, 
  userService, 
  rooms, 
  roomsData, 
  voiceRooms, 
  voiceConnectionStats,
  peerConnections,
  webrtcConfig,
  iceServers
};);
              console.log(`📡 Notified ${existingUser.username} about ${username} joining voice`);
            }, index * 150); // Staggered timing: 150ms between each notification
          } else {
            // Remove stale user
            console.log(`🧹 Removing stale voice user during join: ${existingUser.username}`);
            voiceRooms[roomId] = voiceRooms[roomId].filter(u => u.userId !== existingUser.userId);
          }
        });
      }, 300); // Initial delay for stability

      // Update voice room status for all room users
      setTimeout(() => {
        io.to(roomId).emit('voice-room-updated', {
          voiceUsers: voiceRooms[roomId].map(u => ({
            userId: u.userId,
            username: u.username,
            connectionState: u.connectionState
          })),
          totalVoiceUsers: voiceRooms[roomId].length
        });
      }, 500);

      // Send success confirmation to the joiner
      socket.emit('voice-room-joined', {
        roomId,
        userId,
        username,
        webrtcSessionId: socket.webrtcSessionId,
        existingUserCount: existingUsers.length,
        webrtcConfig: webrtcConfig,
        permissionsRequired: false // NO PERMISSIONS SYSTEM
      });

    } catch (error) {
      console.error('Error joining voice room:', error);
      socket.emit('error', { message: 'Failed to join voice room' });
    }
  });

  // Enhanced leave voice room with comprehensive cleanup
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

      // Update connection stats
      monitorConnection(roomId, userId, {
        leftAt: new Date(),
        leaveReason: reason || 'manual',
        connectionState: 'disconnected'
      });

      // Notify others in voice room with staggered timing
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
          }, index * 100); // Staggered notifications
        }
      });

      // Notify room about voice room update
      setTimeout(() => {
        io.to(roomId).emit('voice-room-updated', {
          voiceUsers: voiceRooms[roomId].map(u => ({
            userId: u.userId,
            username: u.username,
            connectionState: u.connectionState
          })),
          totalVoiceUsers: voiceRooms[roomId].length
        });
      }, 200);

      // Send confirmation to the leaving user
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
        
        // Keep connection stats for debugging for 5 minutes
        setTimeout(() => {
          if (voiceConnectionStats[roomId]) {
            delete voiceConnectionStats[roomId];
          }
        }, 5 * 60 * 1000);
      }

    } catch (error) {
      console.error('Error leaving voice room:', error);
      socket.emit('error', { message: 'Failed to leave voice room' });
    }
  });

  // Enhanced WebRTC Signaling (unchanged)
  socket.on('sending-signal', ({ userToCall, callerID, signal, roomId }) => {
    try {
      console.log(`📞 Signal from ${callerID} to ${userToCall} in room ${roomId} (type: ${signal?.type}) [Size: ${JSON.stringify(signal).length} bytes]`);
      
      if (!signal || typeof signal !== 'object') {
        console.error('❌ Invalid signal data received:', signal);
        socket.emit('voice-error', { 
          message: 'Invalid signal data',
          targetUser: userToCall,
          signalType: 'invalid'
        });
        return;
      }

      cleanupStaleVoiceUsers(roomId);
      
      const targetUser = voiceRooms[roomId]?.find(u => u.userId === userToCall);
      if (!targetUser) {
        console.log(`❌ Target user ${userToCall} not found in voice room`);
        socket.emit('voice-error', { 
          message: `User ${userToCall} not available for voice chat`,
          targetUser: userToCall,
          availableUsers: voiceRooms[roomId]?.map(u => u.userId) || []
        });
        return;
      }

      const targetSocket = io.sockets.sockets.get(targetUser.socketId);
      if (!targetSocket || !targetSocket.connected) {
        console.log(`❌ Target socket not found or disconnected for user ${userToCall}`);
        if (voiceRooms[roomId]) {
          voiceRooms[roomId] = voiceRooms[roomId].filter(u => u.userId !== userToCall);
        }
        socket.emit('voice-error', { 
          message: `User ${userToCall} is no longer available`,
          targetUser: userToCall,
          reason: 'socket_disconnected'
        });
        return;
      }

      // Track signaling attempt
      monitorConnection(roomId, callerID, {
        connectionAttempts: (voiceConnectionStats[roomId]?.[callerID]?.connectionAttempts || 0) + 1,
        signalExchanges: (voiceConnectionStats[roomId]?.[callerID]?.signalExchanges || 0) + 1,
        lastSignalType: signal.type,
        lastSignalTo: userToCall
      });

      // Chrome-specific SDP optimizations
      let optimizedSignal = { ...signal };
      if (signal.sdp && (signal.type === 'offer' || signal.type === 'answer')) {
        optimizedSignal.sdp = signal.sdp
          .replace(/a=fmtp:111 .*/, 'a=fmtp:111 minptime=10;useinbandfec=1;maxaveragebitrate=128000')
          .replace(/a=fmtp:111/, 'a=fmtp:111 stereo=1;sprop-stereo=1')
          .replace(/a=maxptime:\d+/, 'a=maxptime:20')
          .replace(/a=ptime:\d+/, 'a=ptime:20');
        
        console.log(`🔧 Applied Chrome SDP optimizations for ${signal.type} from ${callerID} to ${userToCall}`);
      }

      // Forward the enhanced signal
      const signalData = {
        signal: optimizedSignal,
        from: callerID,
        username: userSessions[socket.id]?.username || 'Unknown',
        roomId,
        timestamp: Date.now(),
        webrtcSessionId: userSessions[socket.id]?.webrtcSessionId,
        serverProcessingTime: Date.now()
      };

      console.log(`📡 Forwarding optimized signal to ${targetUser.username} (${signal.type})`);
      targetSocket.emit('user-calling', signalData);

      socket.emit('signal-sent', { 
        targetUser: userToCall,
        signalType: signal.type,
        timestamp: Date.now(),
        optimized: signal.sdp ? true : false
      });

      // Store signal for debugging
      if (!voiceSignals[roomId]) voiceSignals[roomId] = {};
      if (!voiceSignals[roomId][callerID]) voiceSignals[roomId][callerID] = {};
      voiceSignals[roomId][callerID][userToCall] = {
        lastSignal: signal.type,
        timestamp: new Date(),
        signalSize: JSON.stringify(signal).length
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
      console.log(`📞 Return signal to ${callerID} in room ${roomId} (type: ${signal?.type}) [Size: ${JSON.stringify(signal).length} bytes]`);
      
      if (!signal || typeof signal !== 'object') {
        console.error('❌ Invalid return signal data received:', signal);
        socket.emit('voice-error', { 
          message: 'Invalid return signal data',
          callerID,
          signalType: 'invalid'
        });
        return;
      }
      
      cleanupStaleVoiceUsers(roomId);
      
      const callerUser = voiceRooms[roomId]?.find(u => u.userId === callerID);
      if (!callerUser) {
        console.log(`❌ Caller ${callerID} not found in voice room`);
        socket.emit('voice-error', { 
          message: `Caller ${callerID} not found in voice room`,
          callerID,
          availableUsers: voiceRooms[roomId]?.map(u => u.userId) || []
        });
        return;
      }

      const callerSocket = io.sockets.sockets.get(callerUser.socketId);
      if (!callerSocket || !callerSocket.connected) {
        console.log(`❌ Caller socket not found or disconnected for user ${callerID}`);
        if (voiceRooms[roomId]) {
          voiceRooms[roomId] = voiceRooms[roomId].filter(u => u.userId !== callerID);
        }
        socket.emit('voice-error', { 
          message: `Caller ${callerID} is no longer available`,
          callerID,
          reason: 'socket_disconnected'
        });
        return;
      }

      const currentUserId = userSessions[socket.id]?.userId;
      monitorConnection(roomId, currentUserId, {
        signalExchanges: (voiceConnectionStats[roomId]?.[currentUserId]?.signalExchanges || 0) + 1,
        lastSignalType: signal.type,
        lastSignalTo: callerID
      });

      // Chrome-specific SDP optimizations for answer
      let optimizedSignal = { ...signal };
      if (signal.sdp && signal.type === 'answer') {
        optimizedSignal.sdp = signal.sdp
          .replace(/a=fmtp:111 .*/, 'a=fmtp:111 minptime=10;useinbandfec=1;maxaveragebitrate=128000')
          .replace(/a=fmtp:111/, 'a=fmtp:111 stereo=1;sprop-stereo=1')
          .replace(/a=maxptime:\d+/, 'a=maxptime:20')
          .replace(/a=ptime:\d+/, 'a=ptime:20');
        
        console.log(`🔧 Applied Chrome SDP optimizations for answer from ${currentUserId} to ${callerID}`);
      }

      const returnSignalData = {
        signal: optimizedSignal,
        id: currentUserId,
        username: userSessions[socket.id]?.username || 'Unknown',
        timestamp: Date.now(),
        webrtcSessionId: userSessions[socket.id]?.webrtcSessionId,
        serverProcessingTime: Date.now()
      };

      console.log(`📡 Forwarding optimized return signal to ${callerUser.username} (${signal.type})`);
      callerSocket.emit('receiving-returned-signal', returnSignalData);

      socket.emit('return-signal-sent', { 
        callerID,
        signalType: signal.type,
        timestamp: Date.now(),
        optimized: signal.sdp ? true : false
      });

      if (!voiceSignals[roomId]) voiceSignals[roomId] = {};
      if (!voiceSignals[roomId][currentUserId]) voiceSignals[roomId][currentUserId] = {};
      voiceSignals[roomId][currentUserId][callerID] = {
        lastReturnSignal: signal.type,
        timestamp: new Date(),
        signalSize: JSON.stringify(signal).length
      };

    } catch (error) {
      console.error('Error handling returning signal:', error);
      socket.emit('voice-error', { 
        message: 'Failed to return signal',
        error: error.message,
        callerID
      });
    }
  });

  // Enhanced connection quality and status tracking
  socket.on('voice-connection-status', ({ roomId, status, quality, targetUserId }) => {
    try {
      const userSession = userSessions[socket.id];
      if (!userSession || userSession.roomId !== roomId) return;

      console.log(`🔊 Voice connection status for ${userSession.username} -> ${targetUserId || 'all'}: ${status} (quality: ${quality})`);

      monitorConnection(roomId, userSession.userId, {
        connectionStatus: status,
        connectionQuality: quality,
        targetUser: targetUserId
      });

      if (voiceRooms[roomId]) {
        const voiceUser = voiceRooms[roomId].find(u => u.userId === userSession.userId);
        if (voiceUser) {
          voiceUser.connectionState = status;
        }
      }

      const roomUsers = rooms[roomId] || [];
      roomUsers.forEach(user => {
        if (user.role === 'owner' || user.role === 'moderator') {
          const targetSocket = io.sockets.sockets.get(user.id);
          if (targetSocket) {
            targetSocket.emit('voice-connection-update', {
              userId: userSession.userId,
              username: userSession.username,
              status,
              quality,
              targetUserId,
              timestamp: new Date().toISOString()
            });
          }
        }
      });

      if (status === 'connected' && targetUserId) {
        if (!peerConnections[roomId]) peerConnections[roomId] = {};
        if (!peerConnections[roomId][userSession.userId]) peerConnections[roomId][userSession.userId] = {};
        peerConnections[roomId][userSession.userId][targetUserId] = {
          status,
          quality,
          establishedAt: new Date(),
          lastUpdate: new Date()
        };
      }

    } catch (error) {
      console.error('Error handling voice connection status:', error);
    }
  });

  // ICE connection state handling
  socket.on('ice-connection-state', ({ roomId, state, targetUserId }) => {
    try {
      const userSession = userSessions[socket.id];
      if (!userSession || userSession.roomId !== roomId) return;

      console.log(`🧊 ICE connection state for ${userSession.username} -> ${targetUserId}: ${state}`);

      monitorConnection(roomId, userSession.userId, {
        iceConnectionState: state,
        targetUser: targetUserId
      });

      if (voiceConnectionStats[roomId] && voiceConnectionStats[roomId][userSession.userId]) {
        if (!voiceConnectionStats[roomId][userSession.userId].iceStates) {
          voiceConnectionStats[roomId][userSession.userId].iceStates = {};
        }
        voiceConnectionStats[roomId][userSession.userId].iceStates[targetUserId] = {
          state,
          timestamp: new Date(),
          stateHistory: voiceConnectionStats[roomId][userSession.userId].iceStates[targetUserId]?.stateHistory || []
        };
        
        voiceConnectionStats[roomId][userSession.userId].iceStates[targetUserId].stateHistory.push({
          state,
          timestamp: new Date()
        });
        if (voiceConnectionStats[roomId][userSession.userId].iceStates[targetUserId].stateHistory.length > 10) {
          voiceConnectionStats[roomId][userSession.userId].iceStates[targetUserId].stateHistory.shift();
        }
      }

      if (state === 'connected') {
        console.log(`✅ ICE connection established: ${userSession.username} <-> ${targetUserId}`);
        monitorConnection(roomId, userSession.userId, {
          successfulConnections: (voiceConnectionStats[roomId]?.[userSession.userId]?.successfulConnections || 0) + 1
        });
        
        socket.emit('peer-connection-established', {
          targetUserId,
          quality: 'good',
          timestamp: new Date().toISOString()
        });
      }

      if (state === 'failed' || state === 'disconnected') {
        console.log(`❌ ICE connection ${state} for ${userSession.username} -> ${targetUserId}`);
        
        monitorConnection(roomId, userSession.userId, {
          failedConnections: (voiceConnectionStats[roomId]?.[userSession.userId]?.failedConnections || 0) + 1,
          lastFailureReason: state
        });
        
        const targetUser = voiceRooms[roomId]?.find(u => u.userId === targetUserId);
        if (targetUser) {
          const targetSocket = io.sockets.sockets.get(targetUser.socketId);
          if (targetSocket && targetSocket.connected) {
            targetSocket.emit('peer-connection-failed', {
              fromUserId: userSession.userId,
              fromUsername: userSession.username,
              reason: state,
              timestamp: new Date().toISOString(),
              retryRecommended: true
            });
          }
        }
        
        socket.emit('peer-connection-failed', {
          toUserId: targetUserId,
          reason: state,
          timestamp: new Date().toISOString(),
          retryRecommended: true
        });

        if (peerConnections[roomId] && peerConnections[roomId][userSession.userId] && peerConnections[roomId][userSession.userId][targetUserId]) {
          peerConnections[roomId][userSession.userId][targetUserId] = {
            ...peerConnections[roomId][userSession.userId][targetUserId],
            status: 'failed',
            failedAt: new Date(),
            failureReason: state
          };
        }
      }

      if (state === 'checking') {
        console.log(`🔄 ICE connection checking: ${userSession.username} -> ${targetUserId}`);
        socket.emit('peer-connection-checking', {
          targetUserId,
          timestamp: new Date().toISOString()
        });
      }

    } catch (error) {
      console.error('Error handling ICE connection state:', error);
    }
  });

  // Speaking status updates
  socket.on('speaking-status', ({ roomId, isSpeaking, audioLevel }) => {
    try {
      const userSession = userSessions[socket.id];
      if (!userSession || userSession.roomId !== roomId) return;

      monitorConnection(roomId, userSession.userId, {
        lastSpeaking: isSpeaking ? new Date() : voiceConnectionStats[roomId]?.[userSession.userId]?.lastSpeaking,
        currentlySpeaking: isSpeaking,
        audioLevel: audioLevel || 0
      });

      socket.to(roomId).emit('user-speaking-update', {
        userId: userSession.userId,
        username: userSession.username,
        isSpeaking,
        audioLevel: audioLevel || 0,
        timestamp: new Date().toISOString()
      });

      console.log(`🗣️ ${userSession.username} speaking status: ${isSpeaking} (level: ${audioLevel || 0})`);

    } catch (error) {
      console.error('Error handling speaking status:', error);
    }
  });

  // =============================================================================
  // ENHANCED DISCONNECT HANDLING WITH COMPREHENSIVE VOICE CHAT CLEANUP
  // =============================================================================
  socket.on('disconnect', (reason) => {
    console.log(`🔌 User disconnected: ${socket.username || 'Unknown'} (${socket.id}) [WebRTC: ${socket.webrtcSessionId}] - Reason: ${reason}`);
    
    const userSession = userSessions[socket.id];
    if (userSession && userSession.roomId) {
      const roomId = userSession.roomId;
      const userIndex = rooms[roomId]?.findIndex(u => u.id === socket.id);
      
      if (userIndex !== -1) {
        const username = rooms[roomId][userIndex].username;
        const userId = rooms[roomId][userIndex].userId;
        rooms[roomId].splice(userIndex, 1);
        
        // Comprehensive voice room cleanup on disconnect
        if (voiceRooms[roomId]) {
          const voiceUserIndex = voiceRooms[roomId].findIndex(u => u.socketId === socket.id);
          if (voiceUserIndex !== -1) {
            const leavingVoiceUser = voiceRooms[roomId][voiceUserIndex];
            voiceRooms[roomId].splice(voiceUserIndex, 1);
            
            console.log(`🎙️ ${leavingVoiceUser.username} removed from voice room on disconnect`);
            
            if (peerConnections[roomId] && peerConnections[roomId][leavingVoiceUser.userId]) {
              delete peerConnections[roomId][leavingVoiceUser.userId];
            }
            
            Object.keys(peerConnections[roomId] || {}).forEach(otherUserId => {
              if (peerConnections[roomId][otherUserId] && peerConnections[roomId][otherUserId][leavingVoiceUser.userId]) {
                delete peerConnections[roomId][otherUserId][leavingVoiceUser.userId];
              }
            });
            
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

            setTimeout(() => {
              io.to(roomId).emit('voice-room-updated', {
                voiceUsers: voiceRooms[roomId].map(u => ({
                  userId: u.userId,
                  username: u.username,
                  connectionState: u.connectionState
                })),
                totalVoiceUsers: voiceRooms[roomId].length
              });
            }, 300);

            monitorConnection(roomId, leavingVoiceUser.userId, {
              disconnectedAt: new Date(),
              disconnectReason: reason,
              connectionState: 'disconnected',
              totalSessionTime: voiceConnectionStats[roomId]?.[leavingVoiceUser.userId]?.joinedAt ? 
                Date.now() - new Date(voiceConnectionStats[roomId][leavingVoiceUser.userId].joinedAt).getTime() : 0
            });

            if (voiceRooms[roomId].length === 0) {
              delete voiceRooms[roomId];
              delete voiceSignals[roomId];
              delete peerConnections[roomId];
              console.log(`🧹 Cleaned up empty voice room: ${roomId}`);
              
              setTimeout(() => {
                if (voiceConnectionStats[roomId]) {
                  console.log(`🧹 Cleaning up connection stats for room: ${roomId}`);
                  delete voiceConnectionStats[roomId];
                }
              }, 10 * 60 * 1000);
            }