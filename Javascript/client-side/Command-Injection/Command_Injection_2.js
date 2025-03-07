const { spawn } = require('child_process');

app.post('/ping', (req, res) => {
    const cmd = spawn('ping', [req.body.host]); // ❌ Unvalidated input
    cmd.stdout.on('data', (data) => res.send(data));
});
