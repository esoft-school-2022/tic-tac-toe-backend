const {db} = require('../utils');

/**
 * Получает статистику побед/поражений/ничьих игроков.
 * @return {import('knex').Knex.QueryBuilder<*, *>}
 */
const getStatistics = () => db
  .select({
    login: 'u.login',
    wins: db.raw('count(g.winner = p.number or null)'),
    loses: db.raw('count(g.winner <> p.number or null)'),
    draws: db.raw('count(g.winner is null or null)')
  })
  .from({u: 'users'})
  .leftJoin({p: 'players'}, {'u.id': 'p.user_id'})
  .leftJoin({g: 'games'}, {'p.game_id': 'g.id'})
  .groupBy('u.login');


/**
 *
 * Получает статистику процента побед.
 * @param {int} limit
 * @param {int} offset
 * @param {'desc'|'asc'} order
 * @return {import('knex').Knex.QueryBuilder<*, *>}
 */
const getWinRateStatistics = (limit, offset, order = 'desc') => db
  .select({
    login: 'login',
    winRate: db.raw('wins::float / (wins + loses + draws)::float')
  })
  .from({stats: getStatistics()})
  .orderBy('winRate', order)
  .limit(limit)
  .offset(offset);

module.exports = {
  getStatistics,
  getWinRateStatistics
};