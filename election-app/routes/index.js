const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt'); 
const pool = require('../db');

function ensureLoggedIn(req, res, next) {
  if (req.session.userId) {
    next(); 
  } else {
    res.redirect('/login'); 
  }
}

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
          return res.status(400).send("All fields are required!");
      }
      const hashedPassword = await bcrypt.hash(password, 10);
      await pool.query(
          "INSERT INTO users (name, email, password) VALUES ($1, $2, $3)",
          [name, email, hashedPassword]
      );
      res.redirect('/login'); 
  } catch (err) {
    console.error("Registration error:", err); 
      res.status(500).send("Internal error!");
  }
});

router.post('/login', async (req, res) => {
  console.log("We have reached the POST /login route.");
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).send("All fields are required!");
    }
    const result = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    if (result.rows.length === 0) {
      return res.status(401).send("The email is not registered.");
    }
    const user = result.rows[0];
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).send("The password is incorrect.");
    }
    req.session.userId = user.id; 
    console.log('User ID salvat în sesiune:', req.session.userId);
    res.redirect('/');
  } catch (err) {
    console.error("Authentication error:", err);
    res.status(500).send("Internal error!");
  }
});

router.post('/login', (req, res) => {
  console.log("TEST - POST /login reached");
  res.send("We have reached the POST /login route.");
});

router.get('/profile', ensureLoggedIn, async (req, res) => {
  console.log('Accesăm /profile cu userId din sesiune:', req.session.userId);
  try {
    const result = await pool.query(
      'SELECT name, email FROM users WHERE id = $1',
      [req.session.userId]
    );
    const user = result.rows[0];
    res.render('profile', { user });
  } catch (err) {
    console.error('Error loading profile:', err);
    res.status(500).send('Internal error!');
  }
});

module.exports = router;