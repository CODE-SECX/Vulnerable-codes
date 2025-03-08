// Predictable temp file creation
const fs = require('fs');

function createTempFileVulnerable(data) {
  const tempFileName = 'user_' + Math.random().toString(36).substring(2) + '.json';
  const tempPath = '/tmp/' + tempFileName;
  
  // Vulnerable: predictable location, no access controls, no cleanup
  fs.writeFileSync(tempPath, JSON.stringify(data));
  return tempPath;
}
