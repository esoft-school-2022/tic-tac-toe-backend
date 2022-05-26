const {Server} = require('socket.io');
const {createAdapter} = require('@socket.io/redis-adapter');
const Messengers = require('./messengers');
const {wrap} = require('./utils');

module.exports = ({server, config, db, broker, auth}) => {
  const io = new Server(
    server,
    {
      transports: ['websocket']
    }
  );
  const messengers = Object.values(Messengers).map(
    (Messenger) => new Messenger({io, config, db})
  );

  io.adapter(createAdapter(broker.pub, broker.sub));
  io.use(wrap(auth.initialize));
  io.use(wrap(auth.authenticate));
  io.use((socket, next) => {
    if (socket.request.user) {
      socket.data.id = socket.request.user.id;
      socket.data.login = socket.request.user.login;
      next();
    } else {
      socket.disconnect();
    }
  });
  io.on('connection', async(socket) => {
    for (const messenger of messengers) {
      await messenger.onConnection(socket);
    }
  });

  return async() => {
    for (const messenger of messengers) {
      await messenger.onInit();
    }
  };
};
