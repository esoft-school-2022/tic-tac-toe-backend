const winston = require('winston');
const LokiTransport = require('winston-loki');

module.exports = ({config}) => {
  return winston.createLogger({
    transports: [
      new LokiTransport({
        level: config.logger.level,
        host: config.logger.host,
        labels: {
          app: 'tic-tac-toe'
        }
      }),
      ...config.logger.console ? [
        new winston.transports.Console({
          level: config.logger.level
        })
      ] : []
    ]
  });
};
