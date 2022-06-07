const winston = require('winston');
const LokiTransport = require('winston-loki');

module.exports = ({config}) => {
  return winston.createLogger({
    transports: [
      new LokiTransport({
        ...config.logger,
        labels: {
          app: 'tic-tac-toe'
        }
      }),
      ...config.env === 'development' ? [
        new winston.transports.Console({
          level: config.logger.level
        })
      ] : []
    ]
  });
};
