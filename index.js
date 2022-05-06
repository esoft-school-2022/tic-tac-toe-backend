const express = require('express');
const path = require('path');
const routes = require('./src/routes');
const {catchErrors} = require('./src/middlewares');

const app = express();
const publicDirectory = path.join(__dirname, '/public');

app.use(express.json());
app.use(express.static(publicDirectory));
app.use('/api', routes);
app.get('*', (_, res) => {
  res.sendFile(path.join(publicDirectory, '/index.html'));
});
app.use(catchErrors);

app.listen(process.env.PORT || 3000);
