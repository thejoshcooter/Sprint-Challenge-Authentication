const axios = require('axios');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const secrets = require('../config/secrets');
const { jwtKey } = require('../auth/authenticate');

const { authenticate } = require('../auth/authenticate');
const db = require('../database/dbConfig');

module.exports = server => {
  server.post('/api/register', register);
  server.post('/api/login', login);
  server.get('/api/jokes', authenticate, getJokes);
};


// create token
function generateToken(user) {
  const payload = {
    subject: user.id,
    username: user.username,
  };

  const options = {
    expiresIn: '1d',
  };

  return jwt.sign(payload, secrets.jwtSecret, options);
}

function register(req, res) {
  const credentials = req.body;
  credentials.password = bcrypt.hashSync(credentials.password, 12);
  db('users')
  .insert(credentials)
  .then(id => {
    res.status(201).json(id)
  })
  .catch(err => {
    res.status(500).json(err)
  })
}

function login(req, res) {
  const credentials = req.body;
  db('users')
  .where({ username: credentials.username })
  .first()
  .then(user => {
    if(user && bcrypt.compareSync(credentials.password, user.password)) {
      // res.status(200).json(user)
      const token = generateToken(user);
      res.status(200).json(token)
    } else {
      res.status(401).json({ error: 'invalid login credentials' })
    }
  })
  .catch(err => {
    res.status(500).json({ message: 'error logging in' })
  })
}

function getJokes(req, res) {
  const requestOptions = {
    headers: { accept: 'application/json' },
  };

  axios
    .get('https://icanhazdadjoke.com/search', requestOptions)
    .then(response => {
      res.status(200).json(response.data.results);
    })
    .catch(err => {
      res.status(500).json({ message: 'Error Fetching Jokes', error: err });
    });
}
