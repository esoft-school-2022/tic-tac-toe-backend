/**
 * Собирает метрики.
 * @param {import('prom-client').Registry} metrics
 * @param {string} prefix
 * @returns {import('express').RequestHandler}
 */
const collectMetrics = (metrics, prefix) =>
  (req, res, next) => {
    if (!req.path.match(/\/metrics/)) {
      const labels = {};
      const timer = metrics
        .getSingleMetric(`${prefix}http_request_duration`)
        .startTimer(labels);

      req.on('close', () => {
        labels['status_code'] = res.statusCode;

        timer();
      });
    }

    next();
  };

module.exports = collectMetrics;
