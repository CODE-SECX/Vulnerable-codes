const userCmd = req.body.command;
const result = require('child_process').execSync(`${userCmd}`); // ❌ Allows command injection
