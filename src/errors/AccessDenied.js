class AccessDeniedError extends Error {
  /**
   * Пользователь.
   * @type {string}
   */
  issuer;
  /**
   * Ресурс.
   * @type {string}
   */
  resource;

  /**
   * @param {string} issuer
   * @param {string} resource
   */
  constructor(issuer, resource) {
    super(`Access denied for ${issuer} to ${resource}`);
    this.issuer = issuer;
    this.resource = resource;
  }
}

module.exports = AccessDeniedError;
