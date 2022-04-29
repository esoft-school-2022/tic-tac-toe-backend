module.exports = {
  development: {
    database: {
      client: 'pg',
      connection: {
        host: 'localhost',
        port: 5432,
        user: 'tic-tac-toe',
        password: 'Passw0rd',
        database: 'tic-tac-toe'
      },
      migrations: {
        tableName: 'migrations',
        directory: './migrations'
      }
    }
  }
};
