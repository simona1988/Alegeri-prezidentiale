const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt'); 
const pool = require('../db');

router.get('/', function(req, res, next) {
  res.render('index', { title: 'Express' });
});

router.get('/register', (req, res) => {
  res.render('register');
});

router.get('/login', (req, res) => {
  res.render('login');
});

router.post('/register', async (req, res) => {
  try {
      const { name, email, password } = req.body;
      if (!name || !email || !password) {
          return res.status(400).send("Toate câmpurile sunt obligatorii!");
      }
      const hashedPassword = await bcrypt.hash(password, 10);
      await pool.query(
          "INSERT INTO users (name, email, password) VALUES ($1, $2, $3)",
          [name, email, hashedPassword]
      );
      res.redirect('/login'); 
  } catch (err) {
    console.error("Eroare la înregistrare:", err); 
      res.status(500).send("Eroare internă!");
  }
});

router.post('/login', async (req, res) => {
  console.log("Am intrat în ruta POST /login");
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).send("Toate câmpurile sunt obligatorii!");
    }

    const result = await pool.query("SELECT * FROM users WHERE email = $1", [email]);

    if (result.rows.length === 0) {
      return res.status(401).send("Emailul nu este înregistrat.");
    }

    const user = result.rows[0];
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(401).send("Parola este incorectă.");
    }
    req.session.userId = user.id; 
    res.redirect('/');
  } catch (err) {
    console.error("Eroare la autentificare:", err);
    res.status(500).send("Eroare internă!");
  }
});

router.post('/login', (req, res) => {
  console.log("TEST - POST /login reached");
  res.send("Am ajuns în ruta POST /login");
});


module.exports = router;