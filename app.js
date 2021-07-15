const express = require('express');
const morgan = require('morgan');
const createError = require('http-errors');

require('dotenv').config();

require('./helper/init-mongodb');
// require('./helper/generate_keys');
require('./helper/init-redis');

const { verifyAccessToken } = require('./helper/jwt-helper');
const authRoute = require('./routes/auth.route');

const PORT = process.env.PORT;

const app = express();
app.use(morgan('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.get('/', verifyAccessToken, async (req, res, next) => {
  res.send('Hello World');
});

app.use('/auth', authRoute);

app.use(async (req, res, next) => {
  next(createError.NotFound());
});

app.use((err, req, res, next) => {
  res.status(err.status || 500);
  res.send({
    error: {
      status: err.status || 500,
      message: err.message
    }
  });
});

app.listen(PORT, () => console.log(`Server is listening on port ${PORT}`));
