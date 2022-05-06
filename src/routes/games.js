const {Router} = require('express');
const {
  createGameController,
  getGamesController,
  getGameController,
  updateGameController,
  deleteGameController,
} = require('../controllers');
const {catchPromise} = require('../utils/errorHandling');

const router = Router();

router.post('/', catchPromise(createGameController));
router.get('/', catchPromise(getGamesController));
router.get('/:gameId', catchPromise(getGameController));
router.put('/:gameId', catchPromise(updateGameController));
router.delete('/:gameId', catchPromise(deleteGameController));

module.exports = router;
