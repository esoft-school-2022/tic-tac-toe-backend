module.exports = {
  development: {
    auth: {
      secret: 'super-secret',
    },
    redis: {
      url: 'redis://127.0.0.1:6379'
    },
    database: {
      client: 'pg',
      connection: {
        host: '127.0.0.1',
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
  },
  stage: {
    auth: {
      secret: process.env.AUTH_SECRET,
    },
    redis: {
      url: process.env.REDIS_URL
    },
    database: {
      client: 'pg',
      connection: {
        host: process.env.DB_HOST,
        port: process.env.DB_PORT,
        user: process.env.DB_USER,
        password: process.env.DB_PASS,
        database: process.env.DB_NAME
      },
      pool: {
        min: process.env.DB_MIN_POOL,
        max: process.env.DB_MAX_POOL
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
    redis: {
      url: process.env.REDIS_URL
    },
    database: {
      client: 'pg',
      connection: {
        host: process.env.DB_HOST,
        port: process.env.DB_PORT,
        user: process.env.DB_USER,
        password: process.env.DB_PASS,
        database: process.env.DB_NAME
      },
      pool: {
        min: process.env.DB_MIN_POOL,
        max: process.env.DB_MAX_POOL
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
