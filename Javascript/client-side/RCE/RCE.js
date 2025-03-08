eval(req.body.command);
eval(process.argv[2]);
eval(window.location.search);
eval(`command: ${req.headers['cmd']}`);
eval(req.query.input + 'someText');


const fn = new Function(req.body.code);
new Function(`console.log(${req.params.cmd})`);
Function(`console.log(${window.location.hash})`)();

setTimeout(req.body.delay, 1000);
setInterval(process.argv[3], 2000);
setTimeout(`alert(${window.location.hash})`, 1500);

require(req.query.module);
require(`${process.argv[2]}`);
require(`./modules/${req.headers['mod']}`);

const { exec } = require('child_process');
exec(req.query.command);
spawn(process.argv[2]);
fork(`./scripts/${req.body.script}`);

const vm = require('vm');
vm.runInNewContext(req.body.code);
vm.runInThisContext(process.argv[2]);


const obj = JSON.parse(req.body.data);
deserialize(req.query.payload);

const userCode = `console.log(${req.query.data})`;
eval(userCode);
new Function(userCode)();

const cmd = `powershell.exe ${req.body.input}`;
const bashCmd = `bash -c '${req.query.payload}'`;
