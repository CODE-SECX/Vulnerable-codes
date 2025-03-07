const userCmd = req.query.cmd;
const runCmd = new Function("require('child_process').exec('" + userCmd + "')"); // ❌ Dangerous execution
runCmd();
