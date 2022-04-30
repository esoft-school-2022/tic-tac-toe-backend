class NotFoundError extends Error {
  /**
   * Сущность.
   * @type {string}
   */
  entity;
  /**
   * Идентификатор сущности.
   * @type {int}
   */
  entityId;

  /**
   * @param {string} entity
   * @param {int} entityId
   */
  constructor(entity, entityId) {
    super(`Entity '${entity}' with id=${entityId} not found`);
    this.entity = entity;
    this.entityId = entityId;
  }
}

module.exports = NotFoundError;
