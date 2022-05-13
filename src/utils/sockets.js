/**
 * Оборачивает middleware для сокетов.
 * @param {import('express').RequestHandler} middleware
 * @return {function(socket: import('socket.io').Socket, function): void}
 */
const wrap = (middleware) =>
  (socket, next) => middleware(socket.request, {}, next)

module.exports = {
  wrap
};