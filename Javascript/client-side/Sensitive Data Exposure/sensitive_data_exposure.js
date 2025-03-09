// Example 1: Insecure temporary file creation with predictable naming
const fs = require('fs');
const path = require('path');

function saveUploadedFile(fileData) {
  const tempFileName = 'temp_' + Date.now() + '.dat';
  const tempPath = path.join('/tmp', tempFileName);
  
  // Write to predictable location with no access controls
  fs.writeFileSync(tempPath, fileData);
  return tempPath;
}

// Example 2: Using temporary directory without proper permissions
const os = require('os');

function processUserData(data) {
  const tempdir = os.tmpdir(); // Uses system temp directory
  const userDataFile = path.join(tempdir, 'user_data.json');
  
  // Writes sensitive data to shared temp location
  fs.writeFileSync(userDataFile, JSON.stringify(data));
  
  // Process data
  // ...
  
  // Attempt to delete but might fail, leaving data behind
  try {
    fs.unlinkSync(userDataFile);
  } catch (err) {
    console.error('Failed to clean up temporary file:', err);
  }
}

// Example 3: Temporary file with predictable name based on user input
function createReportFile(username, reportData) {
  // Predictable and potentially manipulable filename
  const tempFileName = `temp_report_${username}.pdf`;
  const tempFilePath = path.join('/var/www/temp', tempFileName);
  
  // Write the file
  fs.writeFileSync(tempFilePath, reportData);
  
  return tempFilePath;
}

// Example 4: Insecure file operations with temporary files
app.post('/upload', (req, res) => {
  const tempPath = path.join(__dirname, 'temporary', req.files.file.name);
  
  // Move uploaded file to temporary location without validation
  fs.renameSync(req.files.file.path, tempPath);
  
  // Process the file
  processFile(tempPath);
  
  res.send('File uploaded successfully');
});

// Example 5: Race condition vulnerability with temporary files
function generateConfig(userId) {
  const tempFileName = `config_${userId}.tmp`;
  
  // Check if file exists first (race condition vulnerability)
  if (!fs.existsSync(tempFileName)) {
    fs.writeFileSync(tempFileName, generateDefaultConfig());
  }
  
  // Modify the file
  const config = JSON.parse(fs.readFileSync(tempFileName));
  config.lastUpdated = new Date().toISOString();
  fs.writeFileSync(tempFileName, JSON.stringify(config));
  
  return config;
}