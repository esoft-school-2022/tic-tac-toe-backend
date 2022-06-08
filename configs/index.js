module.exports = {
  development: {
    auth: {
      secret: 'super-secret',
    },
    broker: {
      url: 'redis://localhost:6379'
    },
    logger: {
      level: 'debug',
      host: 'http://localhost:3100',
      console: 1
    },
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
    broker: {
      url: process.env.REDIS_URL
    },
    logger: {
      level: process.env.LOGGER_LEVEL,
      host: process.env.LOKI_HOST,
      console: Number(process.env.ENABLE_CONSOLE)
    },
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