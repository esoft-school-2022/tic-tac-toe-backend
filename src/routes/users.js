const {Router} = require('express');
const {UsersController} = require('../controllers');
const {catchPromise} = require('../utils');

module.exports = ({db}) => {
  const router = Router();
  const users = new UsersController({db});

  router.post('/', catchPromise(users.create));
  router.get('/', catchPromise(users.get));
  router.get('/:userId', catchPromise(users.find));
  router.put('/:userId', catchPromise(users.update));
  router.delete('/:userId', catchPromise(users.delete));

  return router;
};
