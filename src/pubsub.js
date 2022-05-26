const {createClient} = require('redis');

module.exports = async({config}) => {
  const pub = createClient(config.pubSub);
  const sub = pub.duplicate();

  await pub.connect();
  await sub.connect();

  return {
    pub,
    sub
  };
}