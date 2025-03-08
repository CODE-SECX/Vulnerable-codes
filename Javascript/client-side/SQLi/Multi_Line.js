const sql1 = `
  INSERT INTO orders
  (user_id, amount)
  VALUES (${userInput}, ${totalAmount})
`;

const sql2 = `
  DELETE FROM accounts
  WHERE id = '${userId}'
`;

const sql3 = `
  UPDATE products
  SET price = ${newPrice}
  WHERE id = ${productId}
`;

const sql4 = `
  SELECT *
  FROM users
  WHERE id = (${data.id})
`;

const sql5 = `SELECT * from table where name = 'safe'`;

const regex = /(?s)(?:INSERT\s+INTO|DELETE\s+FROM|UPDATE\s+\w+\s+SET|SELECT\s+.*FROM)\s+.*\$\{[^}]+\}.*/;

console.log(regex.test(sql1)); // true
console.log(regex.test(sql2)); // true
console.log(regex.test(sql3)); // true
console.log(regex.test(sql4)); // true
console.log(regex.test(sql5)); // false