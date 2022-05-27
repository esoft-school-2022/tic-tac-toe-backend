const {Router} = require('express');
const {UsersController} = require('../controllers');
const {catchPromise} = require('../utils');
const {withAccess} = require('../middlewares');

module.exports = ({db}) => {
  const router = Router();
  const users = new UsersController({db});

  router.post(
    '/',
    withAccess({entity: 'users', level: 1 << 1}),
    catchPromise(users.create)
  );
  router.get(
    '/',
    withAccess({entity: 'users', level: 1 << 0}),
    catchPromise(users.get)
  );
  router.get(
    '/:userId',
    withAccess({entity: 'users', getEntityId: (req) => req.params.userId, level: 1 << 0}),
    catchPromise(users.find)
  );
  router.put(
    '/:userId',
    withAccess({entity: 'users', getEntityId: (req) => req.params.userId, level: 1 << 1}),
    catchPromise(users.update)
  );
  router.delete(
    '/:userId',
    withAccess({entity: 'users', getEntityId: (req) => req.params.userId, level: 1 << 2}),
    catchPromise(users.delete)
  );

  return router;
};
