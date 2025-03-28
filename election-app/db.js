const { Pool } = require('pg');

const pool = new Pool({
  user: 'postgres',
  host: 'localhost',
  database: 'presidential_election_db',
  password: 'gadea2788',
  port: 5432,
});

module.exports = pool;
