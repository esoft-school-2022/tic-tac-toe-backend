const {Router} = require('express');
const {GamesController} = require('../controllers');
const {catchPromise} = require('../utils');

module.exports = ({db}) => {
  const router = Router();
  const games = new GamesController({db});

  router.post('/', catchPromise(games.create));
  router.get('/', catchPromise(games.get));
  router.get('/:gameId', catchPromise(games.find));
  router.put('/:gameId', catchPromise(games.update));
  router.delete('/:gameId', catchPromise(games.delete));

  return router;
};
