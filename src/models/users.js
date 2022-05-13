const bcrypt = require('bcrypt');
const {db, handleWhere} = require('../utils');
const {NotFoundError, InappropriateActionError} = require('../errors');

const fieldMap = {
  id: 'u.id',
  login: 'u.login',
  password: 'u.password',
  createdAt: 'u.created_at',
  updatedAt: 'u.updated_at',
  status: 'u.status'
};

/**
 * Создает пользователя.
 * @param {string} login
 * @param {string} password
 * @param {string} status
 * @return {Promise<object>}
 */
const createUser = async(login, password, status = 'active') => {
  const [{id, created_at: createdAt, updated_at: updatedAt}] = await db
    .insert([{
      login,
      password: await bcrypt.hash(password, 6),
      status
    }])
    .into('users')
    .returning(['id', 'login', 'status', 'created_at', 'updated_at']);

  return {id, login, status, createdAt, updatedAt};
};

/**
 * Обновляет пользователя.
 * @param {int} userId
 * @param {string} password
 * @param {'active'|'deleted'} status
 * @return {Promise<void>}
 */
const updateUser = async(userId, {password, status}) => {
  const user = await db
    .first({id: 'id'})
    .from('users')
    .where({id: userId});

  if (!user) {
    throw new NotFoundError('user', userId);
  }

  await db
    .update({
      updated_at: new Date().toISOString(),
      ...password ? {password: await bcrypt.hash(password, 6)} : {},
      ...status ? {status} : {}
    })
    .table('users')
    .where({id: userId});
};

/**
 * Удаляет игрока.
 * @param {int} userId
 * @return {Promise<void>}
 */
const deleteUser = async(userId) => {
  const user = await db
    .first({status: 'status'})
    .from('users')
    .where({id: userId});

  if (!user) {
    throw new NotFoundError('user', userId);
  }

  const {status} = user;

  if (status === 'deleted') {
    throw new InappropriateActionError('Can\'t delete deleted user');
  }

  await db
    .update({
      status: 'deleted'
    })
    .table('users')
    .where({id: userId});
};

/**
 * Получает пользователей.
 * @param {string[]} fields
 * @param {{operator: string, left: string, right: *}[]} filters
 * @param {?string} sort
 * @param {int} limit
 * @param {int} offset
 * @return {import('knex').Knex.QueryBuilder<*, *>}
 */
const getUsers = (fields, filters, sort= null, limit = 10, offset = 0) => {
  const query = db
    .select(
      Object.fromEntries(
        fields.map(
          (field) => [field, fieldMap[field] || field]
        )
      )
    )
    .from({u: 'users'})

  for (const {operator, left, right} of filters) {
    handleWhere(fieldMap[left] || left, operator, right, query);
  }

  if (sort) {
    query.orderBy(fieldMap[sort] || sort, 'desc');
  }

  if (limit) {
    query.limit(limit);
  }

  if (offset) {
    query.offset(offset);
  }

  return query;
}

/**
 * Находит пользователя.
 * @param {int} userId
 * @return {import('knex').Knex.QueryBuilder<*, *>}
 */
const findUser = (userId) => db
  .first(fieldMap)
  .from({u: 'users'})
  .where({'u.id': userId})
  .andWhere({'u.status': 'active'});


module.exports = {
  createUser,
  updateUser,
  deleteUser,
  getUsers,
  findUser
};
