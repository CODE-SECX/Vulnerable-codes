const userInput = req.query.cmd;
eval("require('child_process').exec('" + userInput + "')"); // ❌ RCE via eval()
