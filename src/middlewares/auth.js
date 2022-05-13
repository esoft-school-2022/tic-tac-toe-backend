const passport = require('passport');
const {Strategy, ExtractJwt} = require('passport-jwt');
const config = require('../../configs');
const {verifyAuth} = require('../controllers/auth');

passport.use(
  'jwt',
  new Strategy(
    {
      secretOrKey: config[process.env.NODE_ENV || 'development'].auth.secret,
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ...config[process.env.NODE_ENV || 'development'].auth.options
    },
    verifyAuth
  )
);

module.exports = passport;
