const {Server} = require('socket.io');
const messages = require('./messages');
const {auth} = require('./middlewares');
const {wrap} = require('./utils');

module.exports = ({server, config, db}) => {
  const io = socketIO(server);
  const messengers = Object.values(messages).map((Messenger) => new Messenger({io, config, db}));
  const authMiddleware = auth({config, db});

  io.use(wrap(authMiddleware.initialize({})));
  io.use(wrap(authMiddleware.authenticate('jwt', {}, null)));
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
