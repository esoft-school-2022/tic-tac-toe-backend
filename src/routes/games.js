const {Router} = require('express');
const {
  createGameController,
  getGamesController,
  getGameController,
  updateGameController,
  deleteGameController,
} = require('../controllers');

const router = Router();

router.post('/', createGameController);
router.get('/', getGamesController);
router.get('/:gameId', getGameController);
router.put('/:gameId', updateGameController);
router.delete('/:gameId', deleteGameController);

module.exports = router;
