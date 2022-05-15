const {DAL} = require('../base');
const {NotFoundError, InappropriateActionError} = require('../errors');

class GamesDAL extends DAL {
  fieldMap = {
    id: 'g.id',
    winner: 'g.winner',
    createdAt: 'g.created_at',
    finishedAt: 'g.finished_at',
    deletedAt: 'g.deleted_at',
    playerOne: 'u1.login',
    playerTwo: 'u2.login',
  };

  /**
   * Создает игру.
   * @param {int[]} userIds
   * @param {int} size
   * @return {Promise<int>}
   */
   create = async(userIds, size = 3) => {
    const [{id: gameId}] = await this.db
      .insert([{size}])
      .into('games')
      .returning('id');

    await this.db
      .insert(
        userIds.map(
          (userId, idx) => ({
            user_id: userId,
            game_id: gameId,
            number: idx + 1
          })
        )
      )
      .into('players');

    return gameId;
  }

  /**
   * Заканчивает игру.
   * @param {int} gameId
   * @param {?int} winner
   * @return {Promise<void>}
   */
   update = async(gameId, winner = null) => {
    const game = await this.db
      .first({finishedAt: 'finished_at', deletedAt: 'deleted_at'})
      .from('games')
      .where({id: gameId});

    if (!game) {
      throw new NotFoundError('game', gameId);
    }

    const {finishedAt, deletedAt} = game;

    if (deletedAt) {
      throw new InappropriateActionError('Can\'t finish deleted game');
    }

    if (finishedAt) {
      throw new InappropriateActionError('Can\'t finish finished game');
    }

    await this.db
      .update({
        finished_at: new Date().toISOString(),
        ...winner ? {winner} : {}
      })
      .table('games')
      .where({id: gameId});
  }

  /**
   * Отменяет игру.
   * @param {int} gameId
   * @return {Promise<void>}
   */
   delete = async(gameId) => {
    const game = await this.db
      .first({finishedAt: 'finished_at', deletedAt: 'deleted_at'})
      .from('games')
      .where({id: gameId});

    if (!game) {
      throw new NotFoundError('game', gameId);
    }

    const {finishedAt, deletedAt} = game;

    if (finishedAt) {
      throw new InappropriateActionError('Can\'t cancel finished game');
    }

    if (deletedAt) {
      throw new InappropriateActionError('Can\'t cancel canceled game');
    }

    await this.db
      .update({
        deleted_at: new Date().toISOString()
      })
      .table('games')
      .where({id: gameId});
  };

  /**
   * Получает игры.
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
      .from({g: 'games'})

    for (const {operator, left, right} of filters) {
      this.handleWhere(this.mapField(left), operator, right)(query);
    }

    if (fields.includes('playerOne')) {
      query
        .leftJoin({p1: 'players'}, {'g.id': 'p1.game_id', 'p1.number': 1})
        .leftJoin({u1: 'users'}, {'p1.user_id': 'u1.id'})
    }
    if (fields.includes('playerTwo')) {
      query
        .leftJoin({p2: 'players'}, {'g.id': 'p2.game_id', 'p2.number': 2})
        .leftJoin({u2: 'users'}, {'p2.user_id': 'u2.id'})
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
   * Находит игру.
   * @param {int} gameId
   * @return {import('knex').Knex.QueryBuilder<*, *>}
   */
   find = (gameId) => this.db
     .first(this.fieldMap)
     .from({g: 'games'})
     .leftJoin({p1: 'players'}, {'g.id': 'p1.game_id', 'p1.number': 1})
     .leftJoin({u1: 'users'}, {'p1.user_id': 'u1.id'})
     .leftJoin({p2: 'players'}, {'g.id': 'p2.game_id', 'p2.number': 2})
     .leftJoin({u2: 'users'}, {'p2.user_id': 'u2.id'})
     .where({'g.id': gameId});
}

module.exports = GamesDAL;