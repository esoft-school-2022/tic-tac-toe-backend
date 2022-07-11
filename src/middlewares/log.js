/**
 * Логирует.
 * @param {import('winston').Logger} logger
 * @returns {import('express').RequestHandler}
 */
const logRequests = (logger) =>
  (req, res, next) => {
    req.on('close', () => {
      let level = 'info';

      if (res.statusCode >= 400) {
        level = 'warn';
      }
      if (res.statusCode >= 500) {
        level = 'error';
      }

      logger.log(level, `${req.method} ${req.baseUrl} - ${res.statusCode}`);
    });
    next();
  };

module.exports = logRequests;
