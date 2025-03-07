app.post("/register", (req, res) => {
    let query = "INSERT INTO users (name, email) VALUES ('" + req.body.name + "', '" + req.body.email + "')";
    db.query(query, (err, result) => {
        if (err) throw err;
        res.send("User registered");
    });
});
