module.exports = {
  apps : [{
    name: 'tic-tac-toe',
    script: 'index.js',
    exec_mode: 'cluster',
    instances: 4,
    wait_ready: true
  }]
};
