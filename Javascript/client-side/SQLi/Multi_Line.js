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
