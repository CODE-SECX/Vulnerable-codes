app.get("/user", (req, res) => {
    let query = "SELECT * FROM users WHERE id=" + req.query.id;
    db.query(query, (err, result) => {
        if (err) throw err;
        res.send(result);
    });
});
