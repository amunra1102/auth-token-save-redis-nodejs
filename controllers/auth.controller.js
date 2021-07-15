const createError = require('http-errors');

const User = require('../models/user.model');
const { authScheme } = require('../helper/validation-schema');
const {
  signAccessToken,
  signRefreshToken,
  verifyRefreshToken
} = require('../helper/jwt-helper');
const client = require('../helper/init-redis');


module.exports = {
  register: async (req, res, next) => {
    try {
      const result = await authScheme.validateAsync(req.body);

      const { email, password } = result;

      const found = await User.findOne({ email });
      if (found) {
        throw createError.Conflict(`${email} is already been registered`);
      }

      const newUser = new User({
        email,
        password
      });

      const savedUser = await newUser.save();

      const accessToken = await signAccessToken(savedUser.id);
      const refreshToken = await signRefreshToken(savedUser.id);

      res.send({
        user: savedUser,
        accessToken,
        refreshToken
      });
    } catch (error) {
      if (error.isJoi) {
        error.status = 422;
      }

      next(error);
    }
  },
  login: async (req, res, next) => {
    try {
      const result = await authScheme.validateAsync(req.body);
      const { email, password } = result;

      const found = await User.findOne({ email });
      if (!found) {
        throw createError.NotFound('User not registered');
      }

      const isMatch = await found.isValidPassword(password);
      if (!isMatch) {
        throw createError.Unauthorized('Username/Password not valid');
      }

      const accessToken = await signAccessToken(found.id);
      const refreshToken = await signRefreshToken(found.id);

      res.send({
        accessToken,
        refreshToken
      });
    } catch (error) {
      if (error.isJoi) {
        next(createError.BadRequest('Invalid Username/Password'));
      }

      next(error);
    }
  },
  refreshToken: async (req, res, next) => {
    try {
      const { refreshToken } = req.body;
      if (!refreshToken) {
        throw createError.BadRequest();
      }

      const userId = await verifyRefreshToken(refreshToken);

      const accessToken = await signAccessToken(userId);
      const refToken = await signRefreshToken(userId);

      res.send({
        accessToken,
        refreshToken: refToken
      });
    } catch (error) {
      next(error);
    }
  },
  logout: async (req, res, next) => {
    try {
      const { refreshToken } = req.body;
      if (!refreshToken) {
        throw createError.BadRequest();
      }

      const userId = await verifyRefreshToken(refreshToken);
      client.DEL(userId, (err, value) => {
        if (err) {
          console.log(err.message);
          throw createError.InternalServerError();
        }

        console.log(value);
        res.sendStatus(204);
      });

    } catch (error) {
      next(error);
    }
  }
};
