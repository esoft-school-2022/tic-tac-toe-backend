/**
 * @callback AsyncHandler
 * @param {import('express').Request} req
 * @param {import('express').Response} res
 * @return {Promise<void>}
 */
/**
 * Ловит исключения из обработчиков возвращающих промис.
 * @param {AsyncHandler} handler
 * @return {function(import('express').Request, import('express').Response, import('express').NextFunction): Promise<void>}
 */
const catchPromise =
  (handler) =>
    async(
      req,
      res,
      next
    ) => {
      try {
        await handler(req, res);
      } catch (err) {
        next(err);
      }
    }

module.exports = {
  catchPromise
};
