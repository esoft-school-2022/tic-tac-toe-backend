class InappropriateActionError extends Error {
  /**
   * Причина.
   * @type {string}
   */
  cause;

  /**
   * @param {string} cause
   */
  constructor(cause) {
    super(`Inappropriate action because of '${cause}'`);
    this.cause = cause;
  }
}

module.exports = InappropriateActionError;
