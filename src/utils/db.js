const knex = require('knex');
const config = require('../../configs');

/**
 * Доступ к БД.
 * @type {import('knex').Knex<any, unknown[]>}
 */
const db = knex(config[process.env.NODE_ENV || 'development'].database)

/**
 * Считает количество страниц.
 * @param {int} limit
 * @param {import('knex').Knex.QueryBuilder<*, *>} query
 * @return {import('knex').Knex.QueryBuilder<*, *>}
 */
const countPages = (limit, query) => db
  .first({pageCount: db.raw('ceiling(count(*) / ?)', [limit])})
  .from({t: query})

/**
 * Обрабатывает фильтр.
 * @param {string} left
 * @param {string} operator
 * @param {*} right
 * @param {import('knex').Knex.QueryBuilder<*, *>} query
 * @return {import('knex').Knex.QueryBuilder<*, *>}
 */
const handleWhere = (left, operator, right, query) => {
  if (operator === '=' && right === null) {
    return query.whereNull(left);
  } else if (operator === '<>' && right === null) {
    return query.whereNotNull(left);
  } else {
    return query.where(left, operator, right);
  }
}

module.exports = {
  db,
  countPages,
  handleWhere
};