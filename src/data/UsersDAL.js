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
    status: 'u.status',
    rights: this.db.raw('COALESCE(json_agg(DISTINCT r) FILTER (WHERE r.id IS NOT NULL), \'[]\')'),
    accesses: this.db.raw('COALESCE(json_agg(DISTINCT a) FILTER (WHERE a.id IS NOT NULL), \'[]\')')
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

    await this.db
      .insert([{
        user_id: id,
        entity: 'users',
        entity_id: id,
        level: 1 << 0 | 1 << 1
      }])
      .into('accesses');

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
   * @return {Promise<object[]>}
   */
  get = async (fields, filters, sort= null, limit = 10, offset = 0) => {
    const withRights = fields.includes('rights');
    const withAccesses = fields.includes('accesses');
    const extraFields = ['rights', 'accesses'];
    const query = this.db
      .select(
        Object.fromEntries(
          fields.map(
            (field) => [
              field,
              (withRights || withAccesses) && !extraFields.includes(field) ?
                this.db.raw(`MAX(${this.mapField(field)})`) :
                this.mapField(field)
            ]
          )
        )
      )
      .from({u: 'users'});

    for (const {operator, left, right} of filters) {
      this.handleWhere(this.mapField(left), operator, right)(query);
    }

    if (withRights) {
      query
        .leftJoin({asr: 'assigned_roles'}, {'u.id': 'asr.user_id'})
        .leftJoin({avr: 'available_rights'}, {'asr.role_id': 'avr.role_id'})
        .leftJoin({r: 'rights'}, {'avr.right_id': 'r.id'})
        .groupBy(['u.id']);
    }

    if (withRights) {
      query
        .leftJoin({a: 'accesses'}, {'u.id': 'a.user_id'})
        .groupBy(['u.id']);
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

    const result = await query;

    if (result.accesses) {
      result.accesses = result.accesses.map(({user_id, entity_id, ...rest}) => ({
        ...rest,
        userId: user_id,
        entityId: entity_id
      }));
    }

    return result;
  }

  /**
   * Находит пользователя.
   * @param {int} userId
   * @return {Promise<object>}
   */
  find = async(userId) => {
    const [user] = await this.get(
      [...Object.keys(this.fieldMap).filter((key) => key !== 'password')],
      [
        {
          left: 'id',
          operator: '=',
          right: userId
        },
        {
          left: 'status',
          operator: '=',
          right: 'active'
        }
      ]
    );

    if (!user) {
      throw new NotFoundError('user', userId);
    }

    return user;
  }
}

module.exports = UsersDAL;
