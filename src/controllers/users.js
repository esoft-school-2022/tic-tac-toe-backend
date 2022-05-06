const {getUsers, createUser, updateUser, deleteUser, findUser} = require('../models');
const {NotFoundError} = require('../errors');
const {parseFilter} = require('../utils');

/**
 * Обрабатывает HTTP-запрос на получение пользователей.
 * @param {import('express').Request} req
 * @param {import('express').Response} res
 * @return {Promise<void>}
 */
const getUsersController = async(
  req,
  res
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

  const users = await getUsers(
    fields,
    filters,
    sort,
    limit,
    offset
  );

  res.json(users);
};

/**
 * Обрабатывает HTTP-запрос на создание пользователя.
 * @param {import('express').Request} req
 * @param {import('express').Response} res
 * @return {Promise<void>}
 */
const createUserController = async(
  req,
  res
) => {
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
};

/**
 * Обрабатывает HTTP-запрос на обновление пользователя.
 * @param {import('express').Request} req
 * @param {import('express').Response} res
 * @return {Promise<void>}
 */
const updateUserController = async(
  req,
  res
) => {
  const {userId} = req.params;

  if (Object.keys(req.body).some((key) => !['password', 'status'].includes(key))) {
    res.status(400).json({error: 'Unexpected param!'});
  }

  await updateUser(userId, req.body);

  res.json({success: true});
};

/**
 * Обрабатывает HTTP-запрос на удаление пользователя.
 * @param {import('express').Request} req
 * @param {import('express').Response} res
 * @return {Promise<void>}
 */
const deleteUserController = async(
  req,
  res
) => {
  const {userId} = req.params;

  await deleteUser(userId);

  res.json({success: true});
};

/**
 * Обрабатывает HTTP-запрос на получение пользователя.
 * @param {import('express').Request} req
 * @param {import('express').Response} res
 * @return {Promise<void>}
 */
const getUserController = async(
  req,
  res
) => {
  const {userId} = req.params;
  const game = await findUser(userId);

  if (!game) {
    throw new NotFoundError('user', userId);
  }

  res.json(game);
}

module.exports = {
  createUserController,
  getUsersController,
  getUserController,
  updateUserController,
  deleteUserController
};
