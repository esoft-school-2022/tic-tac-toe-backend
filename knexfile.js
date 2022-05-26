const configs = require('./configs');

module.exports = Object
  .entries(configs)
  .reduce(
    (config, [env, {database}]) => ({
      ...config,
      [env]: database
    }),
    {}
  );
