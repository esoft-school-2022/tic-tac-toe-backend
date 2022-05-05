const {getUsers, createUser, updateUser, deleteUser, findUser} = require('../models');
const {NotFoundError} = require('../errors');
const {parseFilter} = require('../utils');

/**
 * Обрабатывает HTTP-запрос на получение пользователей.
 * @type {import('express').RequestHandler}
 */
const getUsersController = async(
  req,
  res,
  next
) => {
  const fields = req.query.fields?.split(',') || ['id', 'login', 'createdAt'];
  const filters = req.query.filters && parseFilter(req.query.filters) || [];
  const limit = Number(req.query.limit) >= 0 ? Number(req.query.limit) : 10;
  const offset = Number(req.query.offset) || 0;
  const {sort} = req.query;

  if (!filters.some(({left}) => left === 'status')) {
    filters.push({
      left: 'status',
      operator: '=',
      right: 'active'
    });
  }

  try {
    const users = await getUsers(
      fields,
      filters,
      sort,
      limit,
      offset
    );

    res.json(users);
  } catch (err) {
    next(err);
  }
};

/**
 * Обрабатывает HTTP-запрос на создание пользователя.
 * @type {import('express').RequestHandler}
 */
const createUserController = async(
  req,
  res,
  next
) => {
  try {
    const {login, password, status} = req.body;

    if (!login) {
      res.status(400).json({error: "Missing login!"});

      return;
    }

    if (!password) {
      res.status(400).json({error: "Missing password!"});

      return;
    }

    const userId = await createUser(login, password, status);

    res.status(201).json({userId});
  } catch (err) {
    next(err);
  }
};

/**
 * Обрабатывает HTTP-запрос на обновление пользователя.
 * @type {import('express').RequestHandler}
 */
const updateUserController = async(
  req,
  res,
  next
) => {
  const {userId} = req.params;

  if (Object.keys(req.body).some((key) => !['password', 'status'].includes(key))) {
    res.status(400).json({error: 'Unexpected param!'});
  }

  if (!userId) {
    res.status(400).json({error: 'User id expected'});

    return;
  }

  try {
    await updateUser(userId, req.body);

    res.json({success: true});
  } catch (err) {
    next(err);
  }
};

/**
 * Обрабатывает HTTP-запрос на удаление пользователя.
 * @type {import('express').RequestHandler}
 */
const deleteUserController = async(
  req,
  res,
  next
) => {
  const {userId} = req.params;

  if (!userId) {
    res.status(400).json({error: 'User id expected'});

    return;
  }

  try {
    await deleteUser(userId);

    res.json({success: true});
  } catch (err) {
    next(err);
  }
};

/**
 * Обрабатывает HTTP-запрос на получение пользователя.
 * @type {import('express').RequestHandler}
 */
const getUserController = async(
  req,
  res,
  next
) => {
  const {userId} = req.params;

  if (!userId) {
    res.status(400).send({error: 'User id expected'});

    return;
  }

  try {
    const game = await findUser(userId);

    if (!game) {
      next(new NotFoundError('user', userId));
    }

    res.json(game);
  } catch (err) {
    next(err);
  }
}

module.exports = {
  createUserController,
  getUsersController,
  getUserController,
  updateUserController,
  deleteUserController
};
