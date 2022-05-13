const {Router} = require('express');
const {createToken, getResource} = require('../controllers/auth');
const {catchPromise} = require('../utils');
const {auth} = require("../middlewares");

const router = Router();

router.post('/token', catchPromise(createToken));
router.get('/resource', auth.authenticate('jwt', {session: false}, null), getResource);

module.exports = router;
