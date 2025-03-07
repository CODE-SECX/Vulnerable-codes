app.get("/product", (req, res) => {
    let query = "SELECT * FROM products WHERE name='" + req.query.name + "'";
    db.query(query, (err, result) => {
        if (err) throw err;
        res.send(result);
    });
});
