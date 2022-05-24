const config = require('./configs');

module.exports = {
  development: config.development.database,
  stage: config.stage.database,
  production: config.production.database
};
