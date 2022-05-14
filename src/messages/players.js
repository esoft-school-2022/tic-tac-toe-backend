module.exports = {
  onInit: async(io) => {
    setInterval(
      () => {
        io.emit(
          'players:list',
          Object.values(
            Array.from(io.sockets.sockets.values())
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
          )
        );
      },
      2000
    )
  },
  onConnection: async(_, socket) => {
    socket.request.user.isFree = true;
  }
};
