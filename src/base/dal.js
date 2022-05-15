class DAL {
  fieldMap = {};

  constructor({db}) {
    this.db = db;
  }

  /**
   * Добавляет количество страниц.
   * @param {int} limit
   * @return {function(query: import('knex').Knex.QueryBuilder<*, *>): import('knex').Knex.QueryBuilder<*, *>} }
   */
  withPages = (limit) => {
    return (query) => query
      .select({pageCount: this.db.raw('ceiling(count(*) / ?)', [limit])});
  }

  /**
   * Мапит поле.
   * @param {string} field
   * @returns {string}
   */
  mapField = (field) => {
    return this.fieldMap[field] || field;
  }

  /**
   * Обрабатывает фильтр.
   * @param {string} left
   * @param {string} operator
   * @param {*} right
   * @return {function(query: import('knex').Knex.QueryBuilder<*, *>): import('knex').Knex.QueryBuilder<*, *>}}
   */
  handleWhere = (left, operator, right) => {
    return (query) => {
      if (operator === '=' && right === null) {
        return query.whereNull(left);
      } else if (operator === '<>' && right === null) {
        return query.whereNotNull(left);
      } else {
        return query.where(left, operator, right);
      }
    }
  }
}

module.exports = DAL;