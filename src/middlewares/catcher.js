const {NotFoundError, InappropriateActionError} = require("../errors");

/**
 * Перехватывает исключения.
 * @type {import('express').ErrorRequestHandler}
 */
const catchErrors = (
  err,
  _,
  res,
  __
) => {
  if (err instanceof NotFoundError) {
    res.status(404).json({error: err.message, entity: err.entity, entityId: err.entityId});
    res.end();
  } else if (err instanceof InappropriateActionError) {
    res.status(400).json({error: err.message, cause: err.cause});
    res.end();
  } else {
    res.status(500).json({error: 'Internal Server Error'});
    res.end();
  }
};

module.exports = catchErrors;
