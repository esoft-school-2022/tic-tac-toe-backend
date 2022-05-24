const {Messenger} = require('../base');
const {GamesDAL} = require('../models');

class PlayersMessenger extends Messenger {
  constructor({io, db}) {
    super({io});

    this.games = new GamesDAL({db});
  }

  getPlayersList = async () => Array.from(await this.io.fetchSockets())
    .map((anotherSocket) => ({
      id: anotherSocket.data.id,
      login: anotherSocket.data.login,
      isFree: !Array.from(anotherSocket.operator?.rooms || anotherSocket.rooms)
        .some((key) => Boolean(key.match(/game#\d+/))),
      socketId: anotherSocket.id
    }))
    .reduce((players, {id, login, isFree, socketId}) => ({
      ...players,
      [id]: {
        id,
        login,
        isFree: (players[id]?.isFree || true) && isFree,
        socketIds: [...players[id]?.socketIds || [], socketId]
      }
    }), {});

  onInit = async () => {
    setInterval(
      async () => {
        this.io.local.emit(
          'players:list',
          Object.values(await this.getPlayersList())
        );
      },
      2000
    );
  }

  onConnection = async (socket) => {
    socket.data.isFree = true;

    socket.on(
      'players:invite',
      async (userId) => {
        const players = await this.getPlayersList();
        const fromPlayer = players[socket.data.id];
        const toPlayer = players[userId];

        if (fromPlayer && toPlayer && toPlayer.isFree) {
          this.io
            .to(toPlayer.socketIds)
            .emit('players:invited', {from: fromPlayer, to: toPlayer});
        } else {
          socket.emit('players:unavailable');
        }
      }
    );
    socket.on(
      'players:cancel',
      async (userId) => {
        const players = await this.getPlayersList();
        const fromPlayer = players[socket.data.id];
        const toPlayer = players[userId];

        if (fromPlayer && toPlayer && toPlayer.isFree) {
          this.io
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
        this.io
          .to([...from.socketIds, ...to.socketIds])
          .emit('players:declined', {from, to});
      }
    );
    socket.on(
      'players:accept',
      async ({from, to}) => {
        const gameId = await this.games.create([from.id, to.id]);

        this.io
          .to([...from.socketIds, ...to.socketIds])
          .emit('players:accepted', {from, to, gameId});
      }
    );
  }
}

module.exports = PlayersMessenger;
