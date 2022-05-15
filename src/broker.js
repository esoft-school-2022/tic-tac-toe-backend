const {createClient} = require('redis');

module.exports = async({config}) => {
  const pub = createClient(config.redis);
  const sub = pub.duplicate();

  await pub.connect();
  await sub.connect();

  return {
    pub,
    sub
  };
}