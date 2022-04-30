module.exports = {
  development: {
    server: {
      port: 8080
    },
    database: {
      client: 'pg',
      connection: {
        host: 'localhost',
        port: 5432,
        user: 'tic_tac_toe',
        password: 'Passw0rd',
        database: 'tic_tac_toe'
      },
      migrations: {
        tableName: 'migrations',
        directory: './migrations'
      },
      seeds: {
        directory: './seeds'
      }
    }
  }
};
