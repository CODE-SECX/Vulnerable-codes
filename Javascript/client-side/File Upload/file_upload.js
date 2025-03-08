// Example 1: Basic file upload with no validation
app.post('/upload', (req, res) => {
    const file = req.files.uploadedFile;
    const path = './uploads/' + file.name;
    
    file.mv(path, (err) => {
      if (err) return res.status(500).send(err);
      res.send('File uploaded!');
    });
  });
  
  // Example 2: Insecure file extension checking
  function validateFile(file) {
    const extension = file.name.split('.').pop().toLowerCase();
    // Vulnerable: can be bypassed with double extension (malicious.php.jpg)
    return ['jpg', 'jpeg', 'png', 'gif'].includes(extension);
  }
  
  // Example 3: Path traversal vulnerability
  app.post('/saveProfile', (req, res) => {
    const userId = req.body.userId;
    const fileName = req.files.avatar.name;
    // Vulnerable: fileName could contain "../" to escape directory
    const filePath = path.join(__dirname, 'uploads', userId, fileName);
    
    fs.writeFileSync(filePath, req.files.avatar.data);
    res.send('Profile updated');
  });
  
  // Example 4: Insufficient content-type validation
  function checkFileType(file) {
    // Vulnerable: Content-Type can be easily spoofed
    return file.mimetype.startsWith('image/');
  }
  
  // Example 5: Direct file system operations without validation
  app.post('/saveDocument', (req, res) => {
    const content = req.body.content;
    const fileName = req.body.fileName;
    // Vulnerable: fileName could be an executable extension
    fs.writeFile(`./documents/${fileName}`, content, (err) => {
      res.send('Document saved');
    });
  });

  const uploadFile = (file) => {
    if (file.name.split('.').pop() === 'jpg' || file.name.split('.').pop() === 'png') {
        console.log('Valid file type');
        // Process file upload
    } else {
        console.log('Invalid file type');
    }
};


app.post('/upload', (req, res) => {
    if (req.file.mimetype === 'image/jpeg' || req.file.mimetype === 'application/pdf') {
        console.log('Valid file type');
        // Process file upload
    } else {
        console.log('Invalid file type');
        res.status(400).send('Invalid file type');
    }
});
