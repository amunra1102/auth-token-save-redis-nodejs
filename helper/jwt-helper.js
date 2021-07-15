const JWT = require('jsonwebtoken');
const createError = require('http-errors');

const client = require('./init-redis');

module.exports = {
  signAccessToken: userId => new Promise((resolve, reject) => {
    const payload = {};
    const secret = process.env.ACCESS_TOKEN_SECRET_KEY;
    const options = {
      expiresIn: '100s',
      issuer: 'hitachivantara.com',
      audience: userId
    };

    JWT.sign(payload, secret, options, (error, token) => {
      if (error) {
        reject(createError.InternalServerError());
      }

      resolve(token);
    });
  }),
  verifyAccessToken: (req, res, next) => {
    const authHeader = req.headers['authorization'];

    if (!authHeader) {
      return next(createError.Unauthorized());
    }

    const bearerToken = authHeader.split(' ');
    const token = bearerToken[1];

    JWT.verify(token, process.env.ACCESS_TOKEN_SECRET_KEY, (error, payload) => {
      if (error) {
        const message = error.name === 'JsonWebTokenError' ? 'Unauthorized' : error.message;
        return next(createError.Unauthorized(message));
      }

      req.payload = payload;
      next();
    });
  },
  signRefreshToken: userId => new Promise((resolve, reject) => {
    const payload = {};
    const secret = process.env.REFRESH_TOKEN_SECRET_KEY;
    const options = {
      expiresIn: '300s',
      issuer: 'hitachivantara.com',
      audience: userId
    };

    JWT.sign(payload, secret, options, (error, token) => {
      if (error) {
        reject(createError.InternalServerError());
      }

      client.SET(userId, token, 'EX', 300, (err, reply) => {
        if (err) {
          console.log(err.message);
          reject(createError.InternalServerError());
          return;
        }

        resolve(token);

      });
    });
  }),
  verifyRefreshToken: refreshToken => new Promise((resolve, reject) => {
    JWT.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET_KEY, (error, payload) => {
      if (error) {
        reject(createError.Unauthorized());
      }

      const userId = payload.aud;
      client.GET(userId, (err, result) => {
        if (err) {
          console.log(err.message);
          reject(createError.InternalServerError());
          return;
        }

        if (refreshToken === result) {
          return resolve(userId);
        }

        reject(createError.Unauthorized());
      });
    });
  })
};
