app.get('/redirect', (req, res) => {
    // Vulnerable: Redirect to user-provided URL
    res.redirect(req.query.url);
  });

  function validateInput(userPattern, input) {
    // Vulnerable: Using eval flag in regex with user input
    const regex = new RegExp(userPattern, "e");
    return regex.test(input);
  }

  app.post('/register', (req, res) => {
    // Vulnerable: No validation on input length
    const username = req.body.username;
    const bio = req.body.bio;
    
    // Insert potentially oversized data
    saveUser(username, bio);
  });

  app.get('/search', (req, res) => {
    // Vulnerable: Unsanitized search term used in results
    const searchTerm = req.query.q;
    
    res.send(`
      <h2>Search results for: ${searchTerm}</h2>
      <div id="results">...</div>
    `);
  });

  const multer = require('multer');
const upload = multer({ dest: 'uploads/' });

app.post('/upload', upload.single('file'), (req, res) => {
  // Vulnerable: No validation of file type or content
  const uploadedFile = req.file;
  
  // Process file without validation
  processUpload(uploadedFile.path);
  
  res.send('File uploaded successfully');
});

const nodemailer = require('nodemailer');
const transporter = nodemailer.createTransport({/* config */});

app.post('/contact', (req, res) => {
  // Vulnerable: User input directly in email fields
  const mailOptions = {
    from: 'contact@example.com',
    to: req.body.email,
    subject: req.body.subject,
    text: req.body.message
  };
  
  transporter.sendMail(mailOptions);
  res.send('Message sent');
});

app.get('/profile/:id', (req, res) => {
    // Vulnerable: No authorization check before fetching resource
    const profile = fetchById(req.params.id);
    
    res.json(profile);
  });

  app.post('/register', (req, res) => {
    // Vulnerable: No password strength validation
    const password = req.body.password;
    
    // Store password without validation
    createUser(req.body.username, password);
    
    res.send('User registered');
  });

  app.get('/calculate', (req, res) => {
    // Vulnerable: Evaluating user-provided expressions
    const result = eval(req.query.expression);
    
    res.send(`Result: ${result}`);
  });

  $(document).ready(function() {
    // Vulnerable: Using user input in jQuery selector
    $('#' + urlParams.get('tab')).show();
  });

  const handlebars = require('handlebars');

app.post('/render', (req, res) => {
  // Vulnerable: Compiling user-provided template
  const template = handlebars.compile(req.body.template);
  
  const html = template({ data: req.body.data });
  res.send(html);
});

app.use((req, res, next) => {
    // Vulnerable: Setting CORS header from user input
    res.setHeader('Access-Control-Allow-Origin', req.headers.origin || '*');
    next();
  });

  app.post('/config', (req, res) => {
    const defaultConfig = {};
    
    // Vulnerable: Merging user input with objects
    Object.assign(defaultConfig, req.body.config);
    
    applyConfig(defaultConfig);
    res.send('Configuration updated');
  });