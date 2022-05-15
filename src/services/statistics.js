const {db} = require('../utils');

/**
 * Получает статистику побед/поражений/ничьих игроков.
 * @return {import('knex').Knex.QueryBuilder<*, *>}
 */
const getStatistics = () => db
  .select({
    id: 'u.id',
    login: db.raw('max(u.login)'),
    wins: db.raw('count(g.winner = p.number or null)::integer'),
    loses: db.raw('count(g.winner <> p.number or null)::integer'),
    draws: db.raw('count(g.winner is null or null)::integer')
  })
  .from({u: 'users'})
  .leftJoin({p: 'players'}, {'u.id': 'p.user_id'})
  .leftJoin({g: 'games'}, {'p.game_id': 'g.id'})
  .groupBy('u.id');


/**
 *
 * Получает статистику процента побед.
 * @param {int} limit
 * @param {int} offset
 * @param {'desc'|'asc'} order
 * @return {import('knex').Knex.QueryBuilder<*, *>}
 */
const getWinRateStatistics = (limit, offset, order = 'desc') => {
  const query = db
    .select({
      id: 'id',
      login: 'login',
      total: db.raw('(wins + loses + draws)::integer'),
      wins: 'wins',
      loses: 'loses',
      winRate: db.raw('wins::float / (wins + loses + draws)::float')
    })
    .from({stats: getStatistics()})
    .orderBy('winRate', order);

  if (limit) {
    query.limit(limit);
  }

  if (offset) {
    query.offset(offset);
  }

  return query;
}

const getPlayerWinRateStatistics = (userId) => getWinRateStatistics(0, 0)
  .where('id', '=', userId)

module.exports = {
  getStatistics,
  getWinRateStatistics,
  getPlayerWinRateStatistics
};
