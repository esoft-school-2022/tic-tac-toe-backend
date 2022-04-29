const {Router} = require('express');
const {
  createGameController,
  getGamesController,
  updateGameController,
  deleteGameController
} = require('../controllers');

const router = Router();

router.post('/', createGameController);
router.get('/', getGamesController);
router.put('/', updateGameController);
router.delete('/', deleteGameController);

module.exports = router;
