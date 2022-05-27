const {AccessDeniedError} = require('../errors');

const checkAccess = (user, {entity, entityId, level, right}) => {
  if (entity && level) {
    const hasRightAccess = user.rights.some(
      ({entity: rightEntity, level: rightLevel}) =>
        entity === rightEntity && Boolean(level & rightLevel)
    );

    if (entityId) {
      const hasDirectAccess = user.accesses.some(
        ({entity: rightEntity, entityId: rightEntityId, level: rightLevel}) =>
          entity === rightEntity && entityId === rightEntityId && Boolean(level & rightLevel)
      );

      return hasRightAccess || hasDirectAccess;
    }

    return hasRightAccess;
  } else if (right) {
    return user.rights.some(({name}) => name === right);
  }
}

const withAccess = ({entity, level, right, getEntityId}) => (req, res, next) => {
  if (checkAccess(req.user, {entity, entityId: getEntityId && getEntityId(req), level, right})) {
    next();
  } else {
    next(new AccessDeniedError(req.user.login, entity));
  }
};

module.exports = withAccess;
