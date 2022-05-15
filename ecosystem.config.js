module.exports = {
  apps : [{
    name: 'tic-tac-toe',
    script: 'index.js',
    exec_mode: 'cluster',
    instances: 4,
    env: {
      PORT: 3000,
      NODE_ENV: 'development'
    },
    env_development: {
      NODE_ENV: 'development'
    },
    env_production: {
      NODE_ENV: 'production'
    }
  }]
};
