const {NotFoundError, InappropriateActionError} = require("../errors");

/**
 * Перехватывает ошибки.
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
  } else if (err instanceof InappropriateActionError) {
    res.status(400).json({error: err.message, cause: err.cause});
  } else {
    res.status(500).json({error: 'Internal Server Error'});
  }
};

module.exports = catchErrors;
