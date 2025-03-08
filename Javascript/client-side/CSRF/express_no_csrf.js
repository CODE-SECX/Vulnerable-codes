// Express route without CSRF protection
const express = require('express');
const router = express.Router();

router.post('/update-profile', (req, res) => {
  // No CSRF token validation
  const { name, email } = req.body;
  updateUserInDatabase(name, email);
  res.json({ success: true });
});
