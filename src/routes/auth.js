const {Router} = require('express');
const {AuthController} = require('../controllers');
const {catchPromise} = require('../utils');

module.exports = ({config, db, broker}) => {
  const router = Router();
  const authController = new AuthController({config, db, broker});

  router.post(
    '/token',
    catchPromise(authController.createToken)
  );
  router.get(
    '/resource',
    authController.getResource
  );

  return router;
};
