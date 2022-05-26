const {Router} = require('express');
const {AuthController} = require('../controllers');
const {catchPromise} = require('../utils');

module.exports = ({config, db, auth}) => {
  const router = Router();
  const authController = new AuthController({config, db});

  router.post(
    '/token',
    catchPromise(authController.createToken)
  );
  router.get(
    '/resource',
    auth.authenticate,
    authController.getResource
  );

  return router;
};
