const {db, handleWhere} = require('../utils');
const {NotFoundError, InappropriateActionError} = require('../errors');

const fieldMap = {
  id: 'id',
  winner: 'winner',
  createdAt: 'created_at',
  finishedAt: 'finished_at',
  deletedAt: 'deleted_at'
};

/**
 * Создает игру.
 * @param {int[]} userIds
 * @param {int} size
 * @return {Promise<int>}
 */
const startGame = async(userIds, size = 3) => {
  const [{id: gameId}] = await db
    .insert([{size}])
    .into('games')
    .returning('id');

  await db
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
};

/**
 * Заканчивает игру.
 * @param {int} gameId
 * @param {?int} winner
 * @return {Promise<void>}
 */
const finishGame = async(gameId, winner = null) => {
  const game = await db
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

  await db
    .update({
      finished_at: new Date().toISOString(),
      ...winner ? {winner} : {}
    })
    .table('games')
    .where({id: gameId});
};

/**
 * Отменяет игру.
 * @param {int} gameId
 * @return {Promise<void>}
 */
const cancelGame = async(gameId) => {
  const game = await db
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

  await db
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
 * @return {import('knex').Knex.QueryBuilder<*, *>}
 */
const getGames = (fields, filters) => {
  const query = db
    .select(
      Object.fromEntries(
        fields.map(
          (field) => [field, fieldMap[field] || field]
        )
      )
    )
    .from('games');

  for (const {operator, left, right} of filters) {
    handleWhere(fieldMap[left] || left, operator, right, query);
  }

  return query;
}

/**
 * Находит игру.
 * @param {int} gameId
 * @return {import('knex').Knex.QueryBuilder<*, *>}
 */
const findGame = (gameId) => db
  .first(fieldMap)
  .from('games')
  .where({id: gameId});

module.exports = {
  startGame,
  finishGame,
  cancelGame,
  getGames,
  findGame
};