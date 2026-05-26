const express = require("express");
const path = require("path");
const bcrypt = require("bcrypt");
const session = require("express-session");
const fs = require("fs");

const app = express();
const PORT = 3000;
const USERS_FILE = path.join(__dirname, "data", "users.json");

// Ensure data directory exists
if (!fs.existsSync(path.join(__dirname, "data"))) {
  fs.mkdirSync(path.join(__dirname, "data"));
}

// Initialize users file if it doesn't exist
if (!fs.existsSync(USERS_FILE)) {
  fs.writeFileSync(USERS_FILE, JSON.stringify([]));
}

// Middleware
app.use(express.static("public"));
app.use(express.static("views"));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Session configuration
app.use(
  session({
    secret: "hobbyhub-secret-key",
    resave: false,
    saveUninitialized: true,
    cookie: {
      secure: false, // Set to true if using HTTPS
      httpOnly: true,
      maxAge: 24 * 60 * 60 * 1000, // 24 hours
    },
  }),
);

// Helper function to read users from file
function getUsers() {
  const data = fs.readFileSync(USERS_FILE, "utf-8");
  return JSON.parse(data);
}

// Helper function to write users to file
function saveUsers(users) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

// Helper function to find user by email
function findUserByEmail(email) {
  const users = getUsers();
  return users.find((user) => user.email === email);
}

// Helper function to find user by username
function findUserByUsername(username) {
  const users = getUsers();
  return users.find((user) => user.username === username);
}

// Middleware to check if user is logged in
function isLoggedIn(req, res, next) {
  if (req.session && req.session.userId) {
    next();
  } else {
    res.redirect("/login");
  }
}

// Routes

// Signup endpoint
app.post("/api/signup", async (req, res) => {
  const { username, email, password } = req.body;

  // Validation
  if (!username || !email || !password) {
    return res.status(400).json({ message: "All fields are required" });
  }

  if (password.length < 6) {
    return res
      .status(400)
      .json({ message: "Password must be at least 6 characters" });
  }

  // Check if user already exists
  if (findUserByEmail(email)) {
    return res.status(400).json({ message: "Email already registered" });
  }

  if (findUserByUsername(username)) {
    return res.status(400).json({ message: "Username already taken" });
  }

  try {
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create new user
    const users = getUsers();
    const newUser = {
      id: Date.now().toString(),
      username,
      email,
      password: hashedPassword,
      createdAt: new Date().toISOString(),
    };

    users.push(newUser);
    saveUsers(users);

    res.status(201).json({ message: "User created successfully" });
  } catch (error) {
    res.status(500).json({ message: "Signup failed" });
  }
});

// Login endpoint
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;

  // Validation
  if (!email || !password) {
    return res.status(400).json({ message: "Email and password are required" });
  }

  try {
    const user = findUserByEmail(email);

    if (!user) {
      return res.status(401).json({ message: "Invalid email or password" });
    }

    // Compare passwords
    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      return res.status(401).json({ message: "Invalid email or password" });
    }

    // Set session
    req.session.userId = user.id;
    req.session.username = user.username;
    req.session.email = user.email;
    req.session.createdAt = user.createdAt;

    res.json({ message: "Login successful" });
  } catch (error) {
    res.status(500).json({ message: "Login failed" });
  }
});

// Logout endpoint
app.post("/api/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ message: "Logout failed" });
    }
    res.json({ message: "Logged out successfully" });
  });
});

// Get current user info
app.get("/api/user", (req, res) => {
  if (req.session && req.session.userId) {
    res.json({
      id: req.session.userId,
      username: req.session.username,
      email: req.session.email,
      createdAt: req.session.createdAt,
    });
  } else {
    res.status(401).json({ message: "Not logged in" });
  }
});

// Change password endpoint
app.post("/api/change-password", async (req, res) => {
  const { currentPassword, newPassword } = req.body;

  if (!req.session || !req.session.userId) {
    return res.status(401).json({ message: "Not logged in" });
  }

  if (!currentPassword || !newPassword) {
    return res
      .status(400)
      .json({ message: "Current and new passwords are required" });
  }

  if (newPassword.length < 6) {
    return res
      .status(400)
      .json({ message: "New password must be at least 6 characters" });
  }

  try {
    const users = getUsers();
    const user = users.find((u) => u.id === req.session.userId);

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // Verify current password
    const isPasswordValid = await bcrypt.compare(
      currentPassword,
      user.password,
    );

    if (!isPasswordValid) {
      return res.status(401).json({ message: "Current password is incorrect" });
    }

    // Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;

    saveUsers(users);

    res.json({ message: "Password changed successfully" });
  } catch (error) {
    res.status(500).json({ message: "Failed to change password" });
  }
});

// Update profile endpoint
app.put("/api/update-profile", (req, res) => {
  if (!req.session || !req.session.userId) {
    return res.status(401).json({
      message: "Not logged in",
    });
  }

  try {
    const { username, email } = req.body;

    if (!username || !email) {
      return res.status(400).json({
        message: "Username and email are required",
      });
    }

    const users = getUsers();

    const user = users.find((u) => u.id === req.session.userId);

    if (!user) {
      return res.status(404).json({
        message: "User not found",
      });
    }

    // Check duplicate email
    const emailExists = users.find(
      (u) => u.email === email && u.id !== user.id,
    );

    if (emailExists) {
      return res.status(400).json({
        message: "Email already in use",
      });
    }

    // Check duplicate username
    const usernameExists = users.find(
      (u) => u.username === username && u.id !== user.id,
    );

    if (usernameExists) {
      return res.status(400).json({
        message: "Username already taken",
      });
    }

    // Update user
    user.username = username;
    user.email = email;

    saveUsers(users);

    // Update session
    req.session.username = username;
    req.session.email = email;

    res.json({
      message: "Profile updated successfully",
      user,
    });
  } catch (error) {
    console.log(error);

    res.status(500).json({
      message: "Server error",
    });
  }
});

// Delete account endpoint
app.delete("/api/delete-account", (req, res) => {
  if (!req.session || !req.session.userId) {
    return res.status(401).json({ message: "Not logged in" });
  }

  try {
    const users = getUsers();
    const updatedUsers = users.filter((u) => u.id !== req.session.userId);

    saveUsers(updatedUsers);

    // Destroy session
    req.session.destroy((err) => {
      if (err) {
        return res.status(500).json({ message: "Failed to delete account" });
      }
      res.json({ message: "Account deleted successfully" });
    });
  } catch (error) {
    res.status(500).json({ message: "Failed to delete account" });
  }
});

// Static routes
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "views", "index.html"));
});

app.get("/activities", (req, res) => {
  res.sendFile(path.join(__dirname, "views", "activities.html"));
});

app.get("/login", (req, res) => {
  if (req.session && req.session.userId) {
    return res.redirect("/");
  }
  res.sendFile(path.join(__dirname, "views", "login.html"));
});

app.get("/signup", (req, res) => {
  if (req.session && req.session.userId) {
    return res.redirect("/");
  }
  res.sendFile(path.join(__dirname, "views", "signup.html"));
});

app.get("/account", (req, res) => {
  if (!req.session || !req.session.userId) {
    return res.redirect("/login");
  }
  res.sendFile(path.join(__dirname, "views", "account.html"));
});

app.get("/course-drawing", (req, res) => {
  res.sendFile(path.join(__dirname, "views", "course-drawing.html"));
});

app.get("/course-workout", (req, res) => {
  res.sendFile(path.join(__dirname, "views", "course-workout.html"));
});

app.get("/course-reading", (req, res) => {
  res.sendFile(path.join(__dirname, "views", "course-reading.html"));
});

app.get("/course-coloring", (req, res) => {
  res.sendFile(path.join(__dirname, "views", "course-coloring.html"));
});

app.get("/course-cooking", (req, res) => {
  res.sendFile(path.join(__dirname, "views", "course-cooking.html"));
});

app.get("/course-diy", (req, res) => {
  res.sendFile(path.join(__dirname, "views", "course-diy.html"));
});

app.get("/course-music", (req, res) => {
  res.sendFile(path.join(__dirname, "views", "course-music.html"));
});

app.get("/quiz-drawing", (req, res) => {
  res.sendFile(path.join(__dirname, "views", "quiz-drawing.html"));
});

app.get("/quiz-coloring", (req, res) => {
  res.sendFile(path.join(__dirname, "views", "quiz-coloring.html"));
});

app.get("/quiz-cooking", (req, res) => {
  res.sendFile(path.join(__dirname, "views", "quiz-cooking.html"));
});

app.get("/quiz-diy", (req, res) => {
  res.sendFile(path.join(__dirname, "views", "quiz-diy.html"));
});

app.get("/quiz-music", (req, res) => {
  res.sendFile(path.join(__dirname, "views", "quiz-music.html"));
});

app.get("/quiz-reading", (req, res) => {
  res.sendFile(path.join(__dirname, "views", "quiz-reading.html"));
});

app.get("/quiz-workout", (req, res) => {
  res.sendFile(path.join(__dirname, "views", "quiz-workout.html"));
});

app.get("/progress", (req, res) => {
  res.sendFile(path.join(__dirname, "views", "progress.html"));
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
