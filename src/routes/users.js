const {Router} = require('express');
const {UsersController} = require('../controllers');
const {catchPromise} = require('../utils');

module.exports = ({db}) => {
  const router = Router();
  const users = new UsersController({db});

  router.post('/', catchPromise(users.create));
  router.get('/', catchPromise(users.get));
  router.get('/:gameId', catchPromise(users.find));
  router.put('/:gameId', catchPromise(users.update));
  router.delete('/:gameId', catchPromise(users.delete));

  return router;
};
