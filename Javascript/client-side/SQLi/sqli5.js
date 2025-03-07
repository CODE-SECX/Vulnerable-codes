app.post("/delete-user", (req, res) => {
    let query = "DELETE FROM users WHERE id=" + req.body.id;
    db.query(query, (err, result) => {
        if (err) throw err;
        res.send("User deleted");
    });
});
