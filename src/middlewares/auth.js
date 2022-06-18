const passport = require('passport');
const {Strategy, ExtractJwt} = require('passport-jwt');
const {AuthController} = require('../controllers');

module.exports = ({db, config, broker}) => {
  const auth = new AuthController({db, config, broker});

  passport.use(
    'jwt',
    new Strategy(
      {
        secretOrKey: config.auth.secret,
        jwtFromRequest: ExtractJwt.fromExtractors([
          ExtractJwt.fromAuthHeaderAsBearerToken(),
          ExtractJwt.fromUrlQueryParameter('token')
        ]),
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

  return {
    initialize: passport.initialize({}),
    authenticate: passport.authenticate('jwt', {session: false}, null)
  };
};
