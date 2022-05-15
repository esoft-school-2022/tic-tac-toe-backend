const knex = require('knex');

module.exports = ({config}) => {
  return knex(config.database);
};
