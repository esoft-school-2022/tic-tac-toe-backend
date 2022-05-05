const {Router} = require('express');
const {
  createUserController,
  getUsersController,
  getUserController,
  updateUserController,
  deleteUserController
} = require('../controllers');

const router = Router();

router.post('/', createUserController);
router.get('/', getUsersController);
router.get('/:userId', getUserController);
router.put('/:userId', updateUserController);
router.delete('/:userId', deleteUserController);

module.exports = router;
