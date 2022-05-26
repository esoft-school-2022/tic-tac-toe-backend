module.exports = {
  apps : [{
    name: 'tic-tac-toe',
    script: 'index.js',
    exec_mode: 'cluster',
    instances: 4,
    wait_ready: true,
    env: {
      PORT: 12321
    },
    env_development: {
      NODE_ENV: 'development'
    },
    env_production: {
      NODE_ENV: 'production',
      SERVE_STATIC: false
    }
  }]
};
