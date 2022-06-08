const catchErrors = require('./catcher');
const auth = require('./auth');
const withAccess = require('./access');
const logRequests = require('./log');
const collectMetrics = require('./metrics');

module.exports = {
  catchErrors,
  auth,
  withAccess,
  logRequests,
  collectMetrics
};
