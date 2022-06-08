const {Histogram, Registry, collectDefaultMetrics, Gauge} = require('prom-client');

module.exports = ({config}) => {
  const registry = new Registry();

  collectDefaultMetrics({register: registry, prefix: config.metrics.prefix});

  registry.registerMetric(
    new Histogram({
      name: `${config.metrics.prefix}http_request_duration`,
      help: 'duration histogram of http responses',
      labelNames: ['status_code'],
      buckets: [0.003, 0.03, 0.1, 0.3, 1.5, 10]
    })
  );
  registry.registerMetric(
    new Gauge({
      name: `${config.metrics.prefix}up`,
      help: '1 - up; 0 - not up'
    })
  );

  return registry;
};
