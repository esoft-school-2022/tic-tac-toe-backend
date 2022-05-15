class Controller {
  operatorMap = {
    eq: '=',
    neq: '<>',
    gt: '>',
    lt: '<',
    gte: '>=',
    lte: '<=',
    in: 'in',
    nin: 'not in',
    co: 'like',
    sw: 'like',
    ew: 'like',
    nco: 'like',
    nsw: 'like',
    new: 'like'
  };

  /**
   * Парсит значение.
   * @param {string} operator
   * @param {string} value
   * @return {string|any}
   */
  parseValue = (operator, value) => {
    if (['in', 'nin'].includes(operator)) {
      return value
        .split(',')
        .map((arrayValue) => {
          try {
            return JSON.parse(arrayValue.trim());
          } catch (err) {
            return arrayValue.trim();
          }
        });
    } else if (['co', 'nco'].includes(operator)) {
      return `%${value}%`;
    } else if (['sw', 'nsw'].includes(operator)) {
      return `${value}%`;
    } else if (['ew', 'new'].includes(operator)) {
      return `%${value}`;
    } else {
      try {
        return JSON.parse(value);
      } catch (err) {
        return value;
      }
    }
  }

  /**
   * Парсит фильтр.
   * @param {string} filterQuery
   * @return {{operator: string, left: string, value: *}[]}
   */
  parseFilter = (filterQuery) => {
    return filterQuery
      .split('and')
      .reduce(
        (filters, rawFilter) => {
          const [left, operator, ...right] = rawFilter.trim().split(' ');

          return [
            ...filters,
            {
              operator: this.operatorMap[operator],
              left,
              right: this.parseValue(operator, right.join('').trim())
            }
          ];
        },
        []
      );
  }
}

module.exports = Controller;
