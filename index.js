const express = require('express');
const api = require('./src/routes');
const {catchErrors, auth} = require('./src/middlewares');

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

app.listen(process.env.PORT || 8080);
