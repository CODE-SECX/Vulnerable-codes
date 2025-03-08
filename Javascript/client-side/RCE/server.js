const express = require("express");
const fs = require("fs");
const path = require("path");
const app = express();

app.get("/file", (req, res) => {
  const filename = req.query.filename; // Vulnerable
  const filePath = path.join(__dirname, filename);
  fs.readFile(filePath, "utf8", (err, data) => {
    if (err) {
      res.status(500).send("File not found");
    } else {
      res.send(data);
    }
  });
});

app.get("/relative", (req, res) => {
  const filename = req.query.filename;
  const filePath = path.join(__dirname, filename);
  fs.readFile(filePath, "utf8", (err, data) => {
    if (err) {
      res.status(500).send("File not found");
    } else {
      res.send(data);
    }
  });
});

app.get("/absolute", (req, res) => {
  const filename = req.query.filename;
  fs.readFile(filename, "utf8", (err, data) => {
    if (err) {
      res.status(500).send("File not found");
    } else {
      res.send(data);
    }
  });
});

app.get("/encoded", (req, res) => {
  const filename = req.query.filename;
  const filePath = path.join(__dirname, filename);
  fs.readFile(filePath, "utf8", (err, data) => {
    if (err) {
      res.status(500).send("File not found");
    } else {
      res.send(data);
    }
  });
});

app.get("/variable", (req, res) => {
  const filename = req.query.filename;
  const filePath = path.join(__dirname, filename);
  fs.readFile(filePath, "utf8", (err, data) => {
    if (err) {
      res.status(500).send("File not found");
    } else {
      res.send(data);
    }
  });
});

app.listen(3000, () => console.log("Server running on port 3000"));
