const {Messenger} = require('../base');
const {GamesDAL} = require('../models');

class PlayersMessenger extends Messenger {
  constructor({io, db}) {
    super({io});

    this.games = new GamesDAL({db});
  }

  getPlayersList = async() => Object.values(
      Array.from(await this.io.fetchSockets())
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

  onInit = async() => {
    setInterval(
      async() => {
        this.io.emit(
          'players:list',
          await this.getPlayersList()
        );
      },
  2000
    );
  }

  onConnection = async(socket) => {
    socket.request.user.isFree = true;

    socket.on(
      'players:invite',
      async(userId) => {
        const players = await this.getPlayersList();
        const fromPlayer = players.find(({id}) => id === socket.request.user.id);
        const toPlayer = players.find(({id}) => id === userId);

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
      async(userId) => {
        const players = await this.getPlayersList();
        const fromPlayer = players.find(({id}) => id === socket.request.user.id);
        const toPlayer = players.find(({id}) => id === userId);

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
      async({from, to}) => {
        const gameId = await this.games.create([from.id, to.id]);

        this.io
          .to([...from.socketIds, ...to.socketIds])
          .emit('players:accepted', {from, to, gameId});
      }
    );
  }
}

module.exports = PlayersMessenger;
