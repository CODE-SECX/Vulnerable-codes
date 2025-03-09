// Example 1: Handlebars template injection
app.get('/profile', (req, res) => {
    const username = req.query.username;
    const template = handlebars.compile('<div>Hello, ' + username + '!</div>');
    res.send(template({}));
});

// Example 2: EJS template injection
app.post('/render-template', (req, res) => {
    const userTemplate = req.body.template;
    ejs.render(userTemplate, { user: req.user }, (err, html) => {
        res.send(html);
    });
});

// Example 3: Template literal evaluation
function processUserInput(input) {
    const templateString = `Welcome, ${input}!`;
    eval(`const message = \`${templateString}\`;`);
    return message;
}

// Example 4: Pug template rendering with user input
app.get('/page', (req, res) => {
    const userContent = req.query.content;
    const html = pug.render(`div\n  p ${userContent}`, {});
    res.send(html);
});

// Example 5: React with dangerouslySetInnerHTML
function UserProfile({ userData }) {
    return (
        <div className="profile">
            <div dangerouslySetInnerHTML={{ __html: userData.bio }}></div>
        </div>
    );
}

// Example 6: Direct DOM manipulation
function updateUserMessage(userId, message) {
    const element = document.getElementById('user-message-' + userId);
    element.innerHTML = message; // Vulnerable if message contains user input
}

// Example 7: Function constructor with template
function createGreeting(name) {
    return new Function('return "Hello, ' + name + '!";')();
}

// Example 8: Nunjucks template injection
app.get('/template', (req, res) => {
    const templateName = req.query.template;
    const userData = getUserData(req.user.id);
    nunjucks.render(templateName, userData, (err, result) => {
        res.send(result);
    });
});

// Example 9: Lodash template vulnerability
function renderUserTemplate(templateString, userData) {
    const compiled = _.template(templateString);
    return compiled(userData);
}