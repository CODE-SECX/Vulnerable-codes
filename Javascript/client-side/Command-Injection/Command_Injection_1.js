const { exec } = require('child_process');

app.post('/run', (req, res) => {
    exec(req.body.command, (error, stdout, stderr) => {  // ❌ User-controlled input leads to RCE
        res.send(stdout);
    });
});
