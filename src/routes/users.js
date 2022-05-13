const {Router} = require('express');
const {
  createUserController,
  getUsersController,
  getUserController,
  updateUserController,
  deleteUserController
} = require('../controllers');
const {catchPromise} = require("../utils");

const router = Router();

router.post('/', catchPromise(createUserController));
router.get('/', catchPromise(getUsersController));
router.get('/:userId', catchPromise(getUserController));
router.put('/:userId', catchPromise(updateUserController));
router.delete('/:userId', catchPromise(deleteUserController));

module.exports = router;
