const express = require("express");
const bcrypt = require("bcrypt");
const session = require("express-session");

const app = express();
const PORT = 3000;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Session setup
app.use(
    session({
        secret: "codeorbit-secret-key",
        resave: false,
        saveUninitialized: false
    })
);

// Temporary user storage
const users = [];

// Home route
app.get("/", (req, res) => {
    res.json({
        message: "User Authentication API is running successfully!"
    });
});

// Register
app.post("/register", async (req, res) => {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
        return res.status(400).json({
            message: "Username, email and password are required"
        });
    }

    const existingUser = users.find(user => user.email === email);

    if (existingUser) {
        return res.status(409).json({
            message: "User already exists"
        });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = {
        id: users.length + 1,
        username,
        email,
        password: hashedPassword
    };

    users.push(newUser);

    res.status(201).json({
        message: "Registration successful",
        user: {
            id: newUser.id,
            username: newUser.username,
            email: newUser.email
        }
    });
});

// Login
app.post("/login", async (req, res) => {
    const { email, password } = req.body;

    const user = users.find(user => user.email === email);

    if (!user) {
        return res.status(401).json({
            message: "Invalid email or password"
        });
    }

    const passwordMatch = await bcrypt.compare(password, user.password);

    if (!passwordMatch) {
        return res.status(401).json({
            message: "Invalid email or password"
        });
    }

    req.session.userId = user.id;

    res.json({
        message: "Login successful",
        user: {
            id: user.id,
            username: user.username,
            email: user.email
        }
    });
});

// Protected profile route
app.get("/profile", (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({
            message: "Please login first"
        });
    }

    const user = users.find(user => user.id === req.session.userId);

    res.json({
        message: "Welcome to your profile",
        user: {
            id: user.id,
            username: user.username,
            email: user.email
        }
    });
});

// Logout
app.post("/logout", (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.status(500).json({
                message: "Logout failed"
            });
        }

        res.json({
            message: "Logout successful"
        });
    });
});

// Start server
app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});