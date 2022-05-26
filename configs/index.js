module.exports = {
  development: {
    auth: {
      secret: 'super-secret',
    },
    broker: {
      url: 'redis://127.0.0.1:6379'
    },
    serveStatic: true,
    database: {
      client: 'pg',
      connection: 'postgresql://tic_tac_toe:Passw0rd@localhost:5432/tic_tac_toe',
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
  },
  production: {
    auth: {
      secret: process.env.AUTH_SECRET,
    },
    pubSub: {
      url: process.env.REDIS_URL
    },
    serveStatic: Boolean(process.env.SERVE_STATIC),
    database: {
      client: 'pg',
      connection: process.env.DB_URL,
      pool: {
        min: Number(process.env.DB_MIN_POOL),
        max: Number(process.env.DB_MAX_POOL)
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
