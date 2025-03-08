const express = require('express');
const jwt = require('jsonwebtoken');
const app = express();

// JWT secret key (vulnerably weak or exposed)
const secretKey = '123456';  // Weak secret, easily guessable

// Middleware to authenticate JWT without verifying its signature properly
function verifyToken(req, res, next) {
    const token = req.headers['authorization'];

    if (!token) {
        return res.status(403).send('Token required');
    }

    // Decoding the JWT without verifying the signature
    const decodedToken = jwt.decode(token, { complete: true });

    if (!decodedToken) {
        return res.status(403).send('Invalid token');
    }

    // Token payload can be maliciously altered because verification is skipped
    req.user = decodedToken.payload;
    next();
}

app.get('/dashboard', verifyToken, (req, res) => {
    res.send(`Welcome to the dashboard, ${req.user.username}`);
});

app.listen(3000, () => {
    console.log('Server running on port 3000');
});
