const bcrypt = require('bcrypt');
const {DAL} = require('../base');
const {NotFoundError, InappropriateActionError} = require('../errors');

class UsersDAL extends DAL {
  fieldMap = {
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
  create = async(login, password, status = 'active') => {
    const [{id, created_at: createdAt, updated_at: updatedAt}] = await this.db
      .insert([{
        login,
        password: await bcrypt.hash(password, 6),
        status
      }])
      .into('users')
      .returning(['id', 'login', 'status', 'created_at', 'updated_at']);

    return {id, login, status, createdAt, updatedAt};
  }

  /**
   * Обновляет пользователя.
   * @param {int} userId
   * @param {string} password
   * @param {'active'|'deleted'} status
   * @return {Promise<void>}
   */
  update = async(userId, {password, status}) => {
    const user = await this.db
      .first({id: 'id'})
      .from('users')
      .where({id: userId});

    if (!user) {
      throw new NotFoundError('user', userId);
    }

    await this.db
      .update({
        updated_at: new Date().toISOString(),
        ...password ? {password: await bcrypt.hash(password, 6)} : {},
        ...status ? {status} : {}
      })
      .table('users')
      .where({id: userId});
  }

  delete = async(userId) => {
    const user = await this.db
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

    await this.db
      .update({
        status: 'deleted'
      })
      .table('users')
      .where({id: userId});
  }


  /**
   * Получает пользователей.
   * @param {string[]} fields
   * @param {{operator: string, left: string, right: *}[]} filters
   * @param {?string} sort
   * @param {int} limit
   * @param {int} offset
   * @return {import('knex').Knex.QueryBuilder<*, *>}
   */
  get = (fields, filters, sort= null, limit = 10, offset = 0) => {
    const query = this.db
      .select(
        Object.fromEntries(
          fields.map(
            (field) => [field, this.mapField(field)]
          )
        )
      )
      .from({u: 'users'})

    for (const {operator, left, right} of filters) {
      this.handleWhere(this.mapField(left), operator, right)(query);
    }

    if (sort) {
      query.orderBy(this.mapField(sort), 'desc');
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
  find = (userId) => this.db
    .first(this.fieldMap)
    .from({u: 'users'})
    .where({'u.id': userId})
    .andWhere({'u.status': 'active'});
}

module.exports = UsersDAL;
