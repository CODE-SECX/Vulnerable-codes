const query = `SELECT * FROM users WHERE id = ${userInput}`;
connection.query(query);

let sql = `UPDATE accounts SET balance = ${balance} WHERE id = ${id}`;
db.run(sql);

eval(`db.query("DELETE FROM users WHERE email = '${input}'")`);

eval(`db.query("SELECT * FROM users WHERE id = ${userInput}")`);

