const catchErrors = require('./catcher');
const auth = require('./auth');
const withAccess = require('./access');

module.exports = {
  catchErrors,
  auth,
  withAccess
};
