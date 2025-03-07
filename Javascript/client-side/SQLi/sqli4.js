app.post("/update-password", (req, res) => {
    let query = "UPDATE users SET password='" + req.body.password + "' WHERE id=" + req.body.id;
    db.query(query, (err, result) => {
        if (err) throw err;
        res.send("Password updated");
    });
});
