module.exports = async(io, socket) => {
  const intervalId = setInterval(
    () => {
      socket.emit(
        'players:list',
        Object.values(
          Array.from(io.sockets.sockets.values())
            .filter((anotherSocket) =>
              anotherSocket.request.user.id !== socket.request.user.id)
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
  );

  socket.request.user.isFree = true;

  socket.on(
    'disconnecting',
    () => {
      clearInterval(intervalId);
    }
  );
};
