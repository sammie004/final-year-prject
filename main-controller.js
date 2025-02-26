// dependencies
const mysql = require("mysql");
const dotenv = require("dotenv");
const express = require("express");
const bcrypt = require("bcrypt");
const multer = require("multer");
const { bucket } = require('./config/firebaseConfig'); // Ensure this exports the correct bucket
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const bodyParser = require("body-parser");
const cors = require("cors");
const path = require("path");
const http = require('http');
const { Server } = require('socket.io');
const nodemailer = require("nodemailer");

dotenv.config();

const app = express();

// Create HTTP server and attach Socket.IO
const server = http.createServer(app);
const allowedOrigins = ['http://127.0.0.1:5500', 'http://localhost:3000'];
const io = new Server(server, {
  cors: {
    origin: allowedOrigins,
    credentials: true
  }
});

// Set up nodemailer transporter using environment variables
const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST,
  port: process.env.EMAIL_PORT,
  secure: process.env.EMAIL_PORT == 465, // true for 465, false for others
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// Socket.IO setup (even if you're using polling for notifications, this remains available)
io.on('connection', (socket) => {
  console.log("A client connected:", socket.id);

  // Handle authentication for the socket
  socket.on('authenticate', (data) => {
    socket.userId = data.userId;
    console.log("Socket authenticated for user:", socket.userId);
  });

  socket.on('disconnect', () => {
    console.log("Client disconnected:", socket.id);
  });
});

// Handle OPTIONS Preflight Requests
app.options('*', cors());

// Middleware and static files
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(cors({
  origin: allowedOrigins,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Setting up the file storage system with multer
const storage = multer.memoryStorage();
const upload = multer({
  storage: storage,
  limits: { fileSize: 10 * 1024 * 1024 } // 10MB limit
}).single("file");

// Database set-up
const new_connection = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_DATABASE,
});

new_connection.connect((error) => {
  if (error) {
    console.error("Error connecting to the database:", error);
    process.exit(1);
  } else {
    console.log(`Connection to the database established successfully`);
    console.log(`The name of the database is ${process.env.DB_DATABASE}`);
  }
});

// Token creation/validation middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const tokenFromHeader = authHeader && authHeader.split(' ')[1];
  const tokenFromCookie = req.cookies.token;
  const token = tokenFromHeader || tokenFromCookie;

  if (!token || token.trim() === '') {
    console.error("No token provided");
    return res.sendFile(path.join(__dirname, "public", "main-login.html"));
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      console.error("Token verification error:", err);
      return res.sendFile(path.join(__dirname, "public", "main-login.html"));
    }
    req.userId = decoded.userId;
    req.username = decoded.username || decoded.fullName; // use fullName if available
    req.user = { role: decoded.role };
    next();
  });
};

// Middleware to check if the authenticated user has one of the allowed roles
const authorizeRoles = (allowedRoles) => {
  return (req, res, next) => {
    const userRole = req.user && req.user.role;
    if (!userRole) {
      return res.status(401).json({ message: 'User role not found. Please log in again.' });
    }
    if (allowedRoles.includes(userRole)) {
      next();
    } else {
      return res.status(403).json({ message: 'Access denied: insufficient permissions.' });
    }
  };
};

// Sign-up route
app.post('/sign-up', async (req, res) => {
  const { username, email, password, role, department } = req.body;
  const checkUserQuery = 'SELECT * FROM users WHERE username = ? OR email = ?';

  new_connection.query(checkUserQuery, [username, email], async (err, results) => {
    if (err) {
      console.error('Database error during sign-up:', err);
      return res.status(500).json({ message: 'Internal server error' });
    }
    if (results.length > 0) {
      return res.status(409).json({ message: 'User already exists' });
    } else {
      try {
        const saltRounds = 10;
        const hashed_password = await bcrypt.hash(password, saltRounds);
        const insertUserQuery = 'INSERT INTO users (username, email, password, role, department) VALUES (?, ?, ?, ?, ?)';
        new_connection.query(insertUserQuery, [username, email, hashed_password, role, department], (err) => {
          if (err) {
            console.error('Database error during user insertion:', err);
            return res.status(500).json({ message: 'Error adding user to the database' });
          } else {
            return res.status(201).json({ message: 'User has been added successfully' });
          }
        });
      } catch (hashError) {
        console.error('Error hashing password:', hashError);
        return res.status(500).json({ message: 'Error processing your request' });
      }
    }
  });
});

// Login route
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const checkUserQuery = 'SELECT * FROM users WHERE email = ?';

  new_connection.query(checkUserQuery, [email], async (err, results) => {
    if (err) {
      console.error(`Error during login: ${err}`);
      return res.status(500).json({ message: 'Error checking user' });
    }
    if (results.length === 0) {
      return res.status(401).json({ message: 'This user does not exist' });
    }
    const user = results[0];
    try {
      const match = await bcrypt.compare(password, user.password);
      if (match) {
        const token = jwt.sign(
          { userId: user.user_id, fullName: user.full_name, role: user.role },
          process.env.JWT_SECRET,
          { expiresIn: '1h' }
        );
        const cookieOptions = {
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production',
          sameSite: 'strict',
          maxAge: 60 * 60 * 1000
        };
        res.cookie('token', token, cookieOptions);
        console.log("Generated token:", token);
        return res.status(200).json({
          message: `Welcome user: ${user.username} role: ${user.role}`,
          token,
          userID: user.user_id,
          role: user.role,
          username: user.username,
          department: user.department
        });
      } else {
        return res.status(401).json({ message: 'Invalid email or password' });
      }
    } catch (compareError) {
      console.error('Error comparing passwords:', compareError);
      return res.status(500).json({ message: 'Error processing your request' });
    }
  });
});

// File upload route
app.post("/upload", upload, (req, res) => {
  if (!req.file) {
    return res.status(400).json({ message: "No file uploaded" });
  }
  const allowedMimeTypes = ['image/jpeg', 'image/png', 'application/pdf'];
  if (!allowedMimeTypes.includes(req.file.mimetype)) {
    return res.status(400).json({ message: "Invalid file type" });
  }
  const fileName = `${Date.now()}_${req.file.originalname}`;
  const blob = bucket.file(fileName);
  const blobStream = blob.createWriteStream({
    metadata: { contentType: req.file.mimetype },
  });
  blobStream.on("error", (err) => {
    console.error("Error uploading file:", err);
    return res.status(500).json({ message: "Error uploading file" });
  });
  blobStream.on("finish", () => {
    const publicUrl = `https://storage.googleapis.com/${bucket.name}/${fileName}`;
    const insertFileQuery = `INSERT INTO files (file_name, file_path) VALUES (?, ?)`;
    new_connection.query(insertFileQuery, [fileName, publicUrl], (err, result) => {
      if (err) {
        console.error("Error saving file to database:", err);
        return res.status(500).json({ message: "Error saving file information" });
      }
      console.log("File uploaded and stored successfully:", publicUrl);
      return res.status(200).json({
        message: "File uploaded successfully",
        publicUrl,
      });
    });
  });
  blobStream.end(req.file.buffer);
});

// Fetch lecturer data endpoint
app.get('/lecturers', (req, res) => {
  const { department } = req.query;
  if (!department) {
    return res.status(400).json({ message: "Department is required" });
  }
  const query = "SELECT user_id, username FROM users WHERE role = 'lecturer' AND LOWER(department) = LOWER(?)";
  new_connection.query(query, [department], (err, results) => {
    if (err) {
      console.error("Error retrieving lecturers:", err);
      return res.status(500).json({ message: "Server error" });
    }
    res.status(200).json(results);
  });
});

// Result request route
app.post('/requests', (req, res) => {
  const { student_id, course_code, course_title, lecturer_id, level_taken, issue_faced } = req.body;
  const query = `
    INSERT INTO requests (student_id, course_code, course_title, lecturer_id, status, level_taken, issue_faced)
    VALUES (?, ?, ?, ?, 'pending', ?, ?)
  `;
  new_connection.query(query, [student_id, course_code, course_title, lecturer_id, level_taken, issue_faced], (err, result) => {
    if (err) {
      console.error("Error inserting request:", err);
      return res.status(500).json({ message: "Server error" });
    }
    const requestId = result.insertId;
    res.status(201).json({ message: "Request submitted successfully", request_id: requestId });
    const notificationMessage = `New result upload request for ${course_title}`;
    addNotification(lecturer_id, requestId, notificationMessage);

    // Send email to lecturer notifying them of the new request.
    const getLecturerEmailQuery = "SELECT email, username FROM users WHERE user_id = ?";
    new_connection.query(getLecturerEmailQuery, [lecturer_id], (err, results) => {
      if (err) {
        console.error("Error fetching lecturer email:", err);
      } else if (results.length > 0) {
        const lecturerEmail = results[0].email;
        const lecturerName = results[0].username;
        const mailOptions = {
          from: process.env.EMAIL_FROM,
          to: lecturerEmail,
          subject: "New Request Notification",
          text: `Hello ${lecturerName},\n\nYou have a new result upload request for ${course_title} . Please log in to review the request.\n\nThank you.`
        };
        transporter.sendMail(mailOptions, (error, info) => {
          if (error) {
            console.error("Error sending email to lecturer:", error);
          } else {
            console.log("Email sent to lecturer:", info.response);
          }
        });
      }
    });
  });
});

// Endpoint to retrieve requests for a student
app.get('/student-requests', authenticateToken, authorizeRoles(['student']), (req, res) => {
  const studentId = req.userId;
  const query = `
    SELECT request_id, course_code, course_title, lecturer_id, status, created_at, level_taken 
    FROM requests 
    WHERE student_id = ?
    ORDER BY created_at DESC
  `;
  new_connection.query(query, [studentId], (err, results) => {
    if (err) {
      console.error("Error retrieving student requests:", err);
      return res.status(500).json({ message: "Server error" });
    }
    res.status(200).json(results);
  });
});

// Endpoint to fetch requests for a specific lecturer
app.get('/lecturer-requests', authenticateToken, authorizeRoles(['lecturer']), (req, res) => {
  const lecturerId = req.userId;
  const query = "SELECT request_id, student_id, course_code, course_title, status, created_at FROM requests WHERE lecturer_id = ? ORDER BY created_at DESC";
  new_connection.query(query, [lecturerId], (err, results) => {
    if (err) {
      console.error("Error retrieving lecturer requests:", err);
      return res.status(500).json({ message: "Server error" });
    }
    res.status(200).json(results);
  });
});

// GET /requests/:id - Get details for a specific request
app.get('/requests/:id', authenticateToken, (req, res) => {
  const requestId = req.params.id;
  
  const query = "SELECT * FROM requests WHERE request_id = ?";
  new_connection.query(query, [requestId], (err, results) => {
    if (err) {
      console.error("Error fetching request details:", err);
      return res.status(500).json({ message: "Error fetching request details" });
    }
    if (results.length === 0) {
      return res.status(404).json({ message: "Request not found" });
    }
    
    const requestDetails = results[0];
    if (req.user.role === 'student' && req.userId !== requestDetails.student_id) {
      return res.status(403).json({ message: "Access denied" });
    }
    if (req.user.role === 'lecturer' && req.userId !== requestDetails.lecturer_id) {
      return res.status(403).json({ message: "Access denied" });
    }
    
    res.status(200).json(requestDetails);
  });
});

// GET /requests/:id/rejection - Get the rejection reason for a specific request
app.get('/requests/:id/rejection', authenticateToken, (req, res) => {
  const requestId = req.params.id;
  const query = "SELECT student_id, lecturer_id, rejection_reason FROM requests WHERE request_id = ?";
  new_connection.query(query, [requestId], (err, results) => {
    if (err) {
      console.error("Error fetching rejection reason:", err);
      return res.status(500).json({ message: "Internal server error" });
    }
    if (results.length === 0) {
      return res.status(404).json({ message: "Request not found" });
    }
    const request = results[0];
    if (req.user.role === 'student' && req.userId !== request.student_id) {
      return res.status(403).json({ message: "Access denied" });
    }
    if (req.user.role === 'lecturer' && req.userId !== request.lecturer_id) {
      return res.status(403).json({ message: "Access denied" });
    }
    if (!request.rejection_reason) {
      return res.status(404).json({ message: "No rejection reason available" });
    }
    return res.status(200).json({ rejection_reason: request.rejection_reason });
  });
});

// PUT /requests/:id/status - Update the status of a request (with rejection reason support)
app.put('/requests/:id/status', authenticateToken, authorizeRoles(['lecturer']), (req, res) => {
  const requestId = req.params.id;
  const { status, rejectionReason } = req.body;
  const validStatuses = ['approved', 'lecturer_rejected'];

  if (!validStatuses.includes(status)) {
    return res.status(400).json({ message: "Invalid status value" });
  }
  if (status === 'lecturer_rejected' && (!rejectionReason || rejectionReason.trim() === '')) {
    return res.status(400).json({ message: "Rejection reason is required" });
  }

  const rejectionReasonValue = status === 'lecturer_rejected' ? rejectionReason : null;
  const updateQuery = "UPDATE requests SET status = ?, rejection_reason = ? WHERE request_id = ?";
  new_connection.query(updateQuery, [status, rejectionReasonValue, requestId], (err, result) => {
    if (err) {
      console.error("Error updating status:", err);
      return res.status(500).json({ message: "Server error" });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "Request not found" });
    }
    const getQuery = "SELECT student_id, course_title FROM requests WHERE request_id = ?";
    new_connection.query(getQuery, [requestId], (err2, results2) => {
      if (err2) {
        console.error("Error retrieving request details:", err2);
        return res.status(200).json({ message: "Status updated successfully" });
      }
      if (results2.length > 0) {
        const studentId = results2[0].student_id;
        const courseTitle = results2[0].course_title;
        let notificationMessage;
        if (status === 'approved') {
          notificationMessage = "Your request has been approved by the lecturer";
        } else {
          notificationMessage = `Your request was rejected. Reason: ${rejectionReason}`;
        }
        addNotification(studentId, requestId, notificationMessage);
        io.to(`user_${studentId}`).emit('notification', {
          userId: studentId,
          message: notificationMessage
        });
        // Send email to the student regarding the status update.
        const getStudentEmailQuery = "SELECT email, username FROM users WHERE user_id = ?";
        new_connection.query(getStudentEmailQuery, [studentId], (err3, results3) => {
          if (err3) {
            console.error("Error fetching student email:", err3);
          } else if (results3.length > 0) {
            const studentEmail = results3[0].email;
            const studentName = results3[0].username;
            const mailOptions = {
              from: process.env.EMAIL_FROM,
              to: studentEmail,
              subject: "Request Status Update",
              text: `Hello ${studentName},\n\nYour request for ${courseTitle} has been ${status === 'approved' ? 'approved' : 'rejected'}.${
                status === 'lecturer_rejected' ? "\nReason: " + rejectionReason : ""
              }\n\nPlease check the system for details.`
            };
            transporter.sendMail(mailOptions, (error, info) => {
              if (error) {
                console.error("Error sending email to student:", error);
              } else {
                console.log("Email sent to student:", info.response);
              }
            });
          }
        });
      }
      return res.status(200).json({ message: "Status updated successfully" });
    });
  });
});

// Notifications helper: add a notification entry
const addNotification = (userId, requestId, message) => {
  const query = 'INSERT INTO notifications (user_id, request_id, message) VALUES (?, ?, ?)';
  new_connection.query(query, [userId, requestId, message], (err) => {
    if (err) {
      console.error('Error adding notification:', err);
    } else {
      console.log(`Notification added for user ${userId} regarding request ${requestId}`);
    }
  });
};

// Fetch unread notifications for a user
app.get('/notifications', authenticateToken, (req, res) => {
  const userId = req.userId;
  const query = `
    SELECT notification_id, request_id, message, is_read, created_at 
    FROM notifications 
    WHERE user_id = ? AND is_read = FALSE 
    ORDER BY created_at DESC
  `;
  new_connection.query(query, [userId], (err, results) => {
    if (err) {
      console.error('Error fetching notifications:', err);
      return res.status(500).json({ message: 'Error fetching notifications' });
    }
    res.status(200).json(results);
  });
});

// Mark notifications as read
app.put('/notifications/read', authenticateToken, (req, res) => {
  const userId = req.userId;
  const { notificationIds } = req.body;
  if (!notificationIds || !Array.isArray(notificationIds)) {
    return res.status(400).json({ message: 'Invalid request data' });
  }
  const query = 'UPDATE notifications SET is_read = TRUE WHERE user_id = ? AND notification_id IN (?)';
  new_connection.query(query, [userId, notificationIds], (err) => {
    if (err) {
      console.error('Error updating notifications:', err);
      return res.status(500).json({ message: 'Error updating notifications' });
    }
    res.status(200).json({ message: 'Notifications marked as read' });
  });
});

// Logout route
app.post('/logout', (req, res) => {
  res.clearCookie('token');
  console.log("Logout successful");
  res.status(200).json({ message: "Logout successful" });
});

// Routes to serve static pages
app.get('/lecturer-dashboard', authenticateToken, authorizeRoles(['lecturer']), (req, res) => {
  res.sendFile(path.join(__dirname, "public", "lecturer.html"));
});
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, "public", "main-login.html"));
});
app.get('/results-request', authenticateToken, authorizeRoles(['student']), (req, res) => {
  res.sendFile(path.join(__dirname, "public", "request.html"));
});
app.get('/sign-up', (req, res) => {
  res.sendFile(path.join(__dirname, "public", "sign-up.html"));
});
app.get('/student', authenticateToken, authorizeRoles(['student']), (req, res) => {
  res.sendFile(path.join(__dirname, "public", "student.html"));
});
app.get('/lecturer-requests', authenticateToken, authorizeRoles(['lecturer']), (req, res) => {
  res.sendFile(path.join(__dirname, "public", "lecturer.html"));
});
app.get('/request-status', authenticateToken, authorizeRoles(['student']), (req, res) => {
  res.sendFile(path.join(__dirname, "public", "status.html"));
});
app.get('/loading', (req, res) => {
  res.sendFile(path.join(__dirname, "public", "loader.html"));
});

// Start the server using our HTTP server (with Socket.IO)
server.listen(process.env.PORT, () => {
  console.log(`The app is running on port ${process.env.PORT}`);
});

// Global error handling
process.on('unhandledRejection', (err) => {
  console.error('Unhandled Rejection:', err);
  process.exit(1);
});
process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err);
  process.exit(1);
});
