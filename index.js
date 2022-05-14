const http = require('http');
const express = require('express');
const socketIO = require('socket.io');
const api = require('./src/routes');
const {catchErrors, auth} = require('./src/middlewares');
const messages = require('./src/messages');
const {wrap} = require('./src/utils');

const app = express();

app.use(express.json());
app.use(express.static('public', {index: false}));
app.use(auth.initialize({}));
app.use('/api', api);
app.get(
  '*',
  (_, res) =>
    res.sendFile('index.html', {root: 'public'})
);

const server = http.createServer(app);
const io = socketIO(server);

io.use(wrap(auth.initialize({})));
io.use(wrap(auth.authenticate('jwt', {}, null)));
io.use((socket, next) => {
  if (socket.request.user) {
    next();
  } else {
    socket.disconnect();
  }
});
io.on('connection', async(socket) => {
  for (const {onConnection} of Object.values(messages)) {
    await onConnection(io, socket);
  }
});

server.listen(process.env.PORT || 8080, async() => {
  for (const {onInit} of Object.values(messages)) {
    await onInit(io);
  }
});
