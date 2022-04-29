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

module.exports = {
  db,
  countPages
};