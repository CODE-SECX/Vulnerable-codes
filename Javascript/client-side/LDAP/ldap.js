// LDAP Injection - Basic Pattern
const ldap = require('ldapjs');
const client = ldap.createClient({ url: 'ldap://localhost:389' });

app.post('/search', (req, res) => {
    const filter = `(uid=${req.body.username})`; // Injection Point
    client.search('dc=example,dc=com', { filter: filter }, (err, result) => {
        if (err) return res.status(500).send('Error');
        res.send(result);
    });
});

// LDAP Injection - Filter Construction
app.get('/user', (req, res) => {
    const searchFilter = `(|(uid=${req.query.uid})(mail=${req.query.email}))`; // Injection Point
    client.search('dc=example,dc=com', { filter: searchFilter }, (err, result) => {
        if (err) return res.status(500).send('Error');
        res.send(result);
    });
});

// LDAP Injection - String Concatenation
app.get('/account', (req, res) => {
    const filter = "(objectClass=user)" + `(cn=${req.params.cn})`; // Injection Point
    client.search('dc=example,dc=com', { filter: filter }, (err, result) => {
        if (err) return res.status(500).send('Error');
        res.send(result);
    });
});

// LDAP Injection - Template Literal
app.get('/info', (req, res) => {
    const filter = `(uid=${req.body.username})`;
    const query = `(&(objectClass=person)(uid=${req.body.username}))`; // Injection Point
    client.search('dc=example,dc=com', { filter: query }, (err, result) => {
        if (err) return res.status(500).send('Error');
        res.send(result);
    });
});

// LDAP Injection - Unsanitized DN
app.post('/bind', (req, res) => {
    const dn = `cn=${req.body.username},dc=example,dc=com`; // Injection Point
    client.bind(dn, req.body.password, (err) => {
        if (err) return res.status(500).send('Error');
        res.send('Authenticated');
    });
});

// LDAP Injection - Common LDAP Methods
app.post('/modify', (req, res) => {
    const dn = `cn=${req.body.username},dc=example,dc=com`; // Injection Point
    const change = new ldap.Change({
        operation: 'replace',
        modification: { displayName: req.body.newName }
    });
    client.modify(dn, change, (err) => {
        if (err) return res.status(500).send('Error');
        res.send('Modified');
    });
});

// LDAP Injection - Missing Escaping
app.get('/unsafe-search', (req, res) => {
    const unsafeFilter = `(uid=${req.query.unsafeInput})`; // Injection Point (No escaping)
    client.search('dc=example,dc=com', { filter: unsafeFilter }, (err, result) => {
        if (err) return res.status(500).send('Error');
        res.send(result);
    });
});

// LDAP Injection - Special Characters
app.get('/special-search', (req, res) => {
    const specialFilter = `(|(uid=${req.query.user})(mail=${req.query.mail}))`; // Injection Point
    client.search('dc=example,dc=com', { filter: specialFilter }, (err, result) => {
        if (err) return res.status(500).send('Error');
        res.send(result);
    });
});
