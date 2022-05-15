const {DAL} = require('../base');

class StatisticsDAL extends DAL {
  /**
   * Получает статистику побед/поражений/ничьих игроков.
   * @return {import('knex').Knex.QueryBuilder<*, *>}
   */
   getStatistics = () => this.db
      .select({
        id: 'u.id',
        login: this.db.raw('max(u.login)'),
        wins: this.db.raw('count(g.winner = p.number or null)::integer'),
        loses: this.db.raw('count(g.winner <> p.number or null)::integer'),
        draws: this.db.raw('count(g.winner is null or null)::integer')
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
   getWinRateStatistics = (limit, offset, order = 'desc') => {
    const query = this.db
      .select({
        id: 'id',
        login: 'login',
        total: this.db.raw('(wins + loses + draws)::integer'),
        wins: 'wins',
        loses: 'loses',
        winRate: this.db.raw('wins::float / (wins + loses + draws)::float')
      })
      .from({stats: this.getStatistics()})
      .orderBy('winRate', order);

    if (limit) {
      query.limit(limit);
    }

    if (offset) {
      query.offset(offset);
    }

    return query;
  }

  /**
   * Получает статистику по игроку
   * @param {number} userId
   * @return {Promise<object>}
   */
  getPlayerWinRateStatistics = async(userId) => {
    const [userStats] = await this.getWinRateStatistics(0, 0)
      .where('id', '=', userId);

    return userStats;
  }
}

module.exports = StatisticsDAL;
