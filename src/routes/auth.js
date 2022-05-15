const {Router} = require('express');
const {AuthController} = require('../controllers');
const {catchPromise} = require('../utils');

module.exports = ({config, db, authenticate}) => {
  const router = Router();
  const auth = new AuthController({config, db});

  router.post(
    '/token',
    catchPromise(auth.createToken)
  );
  router.get(
    '/resource',
    authenticate,
    auth.getResource
  );

  return router;
};
