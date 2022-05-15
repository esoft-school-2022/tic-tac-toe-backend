const passport = require('passport');
const {Strategy, ExtractJwt} = require('passport-jwt');
const {AuthController} = require('../controllers');

module.exports = ({db, config}) => {
  const auth = new AuthController({db, config});

  passport.use(
    'jwt',
    new Strategy(
      {
        secretOrKey: config.auth.secret,
        jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
        ...config.auth.options
      },
      auth.verifyAuth
    )
  );
  passport.serializeUser((user, done) => {
    if (user) {
      done(null, user);
    }
  });
  passport.deserializeUser((id, done) => {
    done(null, id);
  });

  return passport;
};
