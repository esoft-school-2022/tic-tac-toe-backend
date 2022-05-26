const {Messenger} = require('../base');
const {GamesDAL} = require('../data');
const PlayersMessenger = require('./PlayersMessenger');
const {TicTacToe} = require('../entities/TicTacToe');

class GamesMessenger extends Messenger {
  constructor({io, db}) {
    super({io});

    this.games = new GamesDAL({db});
    this.playersMessenger = new PlayersMessenger({io, db}); // TODO: убрать костыль
  }

  onInit = async() => {
    // Empty
  }

  onConnection = async(socket) => {
    socket.on(
      'games:connect',
      async(gameId) => {
        const game = await this.games.find(gameId);

        if (game.finishedAt) {
          socket.emit('games:already-finished');

          return;
        } else if (game.playerOne !== socket.data.login && game.playerTwo !== socket.data.login) {
          socket.emit('games:not-invited');

          return;
        }

        socket.join(`game#${gameId}`);
        socket.emit('games:connected', game);
      }
    );
    socket.on(
      'games:make-move',
      async(gameId, position) => {
        const game = await this.games.find(gameId);

        if (game.finishedAt) {
          socket.emit('games:already-finished');

          return;
        } else if (game.playerOneId !== socket.data.id && game.playerTwoId !== socket.data.id) {
          socket.emit('games:not-invited');

          return;
        }

        try {
          const ticTacToe = new TicTacToe(game.size, game.playerOneId, game.playerTwoId);

          ticTacToe.load(
            game.moves
              .filter(Boolean)
              .sort((left, right) => left.number - right.number)
              .map(({position: playedPosition}) => playedPosition)
          );
          const currentPlayer = ticTacToe.makeMove(position, Number(game.playerTwoId === socket.data.id));
          const nextPlayer = ticTacToe.currentPlayer;
          const player = Number(currentPlayer.symbol === 'O') + 1;

          try {
            await this.games.addMove(gameId, ticTacToe.moves.length, position);

            this.io
              .in(`game#${gameId}`)
              .emit('games:move-made', {position, player, currentPlayer, nextPlayer});

            if (ticTacToe.isWinner(currentPlayer) || ticTacToe.isDraw) {
              const winner = !ticTacToe.isDraw ? currentPlayer : null;

              await this.games.update(gameId, player);

              this.io
                .in(`game#${gameId}`)
                .emit('games:finished', {winner, winPosition: ticTacToe.winPosition});
              this.io
                .in(`game#${gameId}`)
                .socketsLeave(`game#${gameId}`);
            }
          } catch (err) {
            socket.emit('games:error', 'Internal Server Error');
          }
        } catch (err) {
          socket.emit('games:error', err.message);
        }
      }
    );
    socket.on(
      'games:message',
      async(gameId, message) => {
        const game = await this.games.find(gameId);

        if (game.finishedAt) {
          socket.emit('games:already-finished');

          return;
        } else if (game.playerOneId !== socket.data.id && game.playerTwoId !== socket.data.id) {
          socket.emit('games:not-invited');

          return;
        }

        this.io
          .in(`game#${gameId}`)
          .emit('games:message', {player: socket.data.login, message})
      }
    )
    socket.on(
      'disconnect',
      async() => {
        const players = await this.playersMessenger.getPlayersList();
        const player = players[socket.data.id];

        if (!player) {
          const activeGames = await Promise.all([
            this.games.get(
              ['id', 'playerOneId', 'playerTwoId'],
              [
                {
                  left: 'playerOneId',
                  operator: '=',
                  right: socket.data.id
                },
                {
                  left: 'finishedAt',
                  operator: 'is',
                  right: null
                },
                {
                  left: 'deletedAt',
                  operator: 'is',
                  right: null
                }
              ]
            ),
            this.games.get(
              ['id', 'playerOneId', 'playerTwoId'],
              [
                {
                  left: 'playerTwoId',
                  operator: '=',
                  right: socket.data.id
                },
                {
                  left: 'finishedAt',
                  operator: 'is',
                  right: null
                },
                {
                  left: 'deletedAt',
                  operator: 'is',
                  right: null
                }
              ]
            )
          ]);

          if (!activeGames.flat().length) {
            return;
          }

          await this.games.updateMany(
            activeGames.map(
              (activesGamesSet, offset) =>
                activesGamesSet.map(
                  ({id}) => ({
                    id,
                    winner: 2 - offset
                  })
                )
            ).flat()
          );

          for (const offset in activeGames) {
            activeGames[offset]
              .reduce((toRooms, {id}) => toRooms.in(`game#${id}`), this.io)
              .emit('games:finished', {winner: 2 - offset});
          }
        }
      }
    );
  }
}

module.exports = GamesMessenger;
