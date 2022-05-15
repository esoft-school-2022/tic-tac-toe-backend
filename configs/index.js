module.exports = {
  development: {
    auth: {
      secret: 'super-secret',
    },
    redis: {},
    database: {
      client: 'pg',
      connection: {
        host: 'localhost',
        port: 5432,
        user: 'tic_tac_toe',
        password: 'Passw0rd',
        database: 'tic_tac_toe'
      },
      pool: {
        min: 4,
        max: 16
      },
      migrations: {
        tableName: 'migrations',
        directory: './db/migrations'
      },
      seeds: {
        directory: './db/seeds'
      }
    }
  }
};
