const {startGame} = require("../models");
const getPlayersList = async(io) =>
  Object.values(
    Array.from(await io.fetchSockets())
      .map((anotherSocket) => ({
        id: anotherSocket.request.user.id,
        login: anotherSocket.request.user.login,
        isFree: anotherSocket.request.user.isFree,
        socketId: anotherSocket.id
      }))
      .reduce((players, {id, login, isFree, socketId}) => ({
        ...players,
        [id]: {id, login, isFree, socketIds: [...players[id]?.socketIds || [], socketId]}
      }), {})
  );

module.exports = {
  onInit: async(io) => {
    setInterval(
      async() => {
        io.emit(
          'players:list',
          await getPlayersList(io)
        );
      },
      2000
    );
  },
  onConnection: async(io, socket) => {
    socket.request.user.isFree = true;

    socket.on(
      'players:invite',
      async(userId) => {
        const players = await getPlayersList(io);
        const fromPlayer = players.find(({id}) => id === socket.request.user.id);
        const toPlayer = players.find(({id}) => id === userId);

        if (fromPlayer && toPlayer && toPlayer.isFree) {
          io.to(toPlayer.socketIds).emit('players:invited', {from: fromPlayer, to: toPlayer});
        } else {
          socket.emit('players:unavailable');
        }
      }
    );
    socket.on(
      'players:cancel',
      async(userId) => {
        const players = await getPlayersList(io);
        const fromPlayer = players.find(({id}) => id === socket.request.user.id);
        const toPlayer = players.find(({id}) => id === userId);

        if (fromPlayer && toPlayer && toPlayer.isFree) {
          io
            .to([...fromPlayer.socketIds, ...toPlayer.socketIds])
            .emit('players:cancelled', {from: fromPlayer, to: toPlayer});
        } else {
          socket.emit('players:unavailable');
        }
      }
    );
    socket.on(
      'players:decline',
      ({from, to}) => {
        io
          .to([...from.socketIds, ...to.socketIds])
          .emit('players:declined', {from, to});
      }
    );
    socket.on(
      'players:accept',
      async({from, to}) => {
        const gameId = await startGame([from.id, to.id]);

        io
          .to([...from.socketIds, ...to.socketIds])
          .emit('players:accepted', {from, to, gameId});
      }
    );
  }
};
