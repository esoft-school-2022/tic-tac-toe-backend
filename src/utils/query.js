const operatorMap = {
  eq: '=',
  neq: '<>',
  gt: '>',
  lt: '<',
  gte: '>=',
  lte: '<=',
  pr: 'in',
  npr: 'not in',
  co: 'like',
  sw: 'like',
  ew: 'like'
};

/**
 * Парсит значение.
 * @param {string} operator
 * @param {string} value
 * @return {string|any}
 */
const parseValue = (operator, value) => {
  if (['pr', 'npr'].includes(operator)) {
    return value.split(',').map((arrayValue) => {
      try {
        return JSON.parse(arrayValue.trim());
      } catch (err) {
        return arrayValue.trim();
      }
    });
  } else if (operator === 'co') {
    return `%${value}%`;
  } else if (operator === 'sw') {
    return `${value}%`;
  } else if (operator === 'ew') {
    return `%${value}`;
  } else {
    try {
      return JSON.parse(value);
    } catch (err) {
      return value;
    }
  }
};

/**
 * Парсит фильтр.
 * @param {string} filterQuery
 * @return {{operator: string, left: string, value: *}[]}
 */
const parseFilter = (filterQuery) => filterQuery
    .split('and')
    .reduce(
      (filters, rawFilter) => {
        const [left, operator, right] = rawFilter.trim().split(' ', 3);

        return [
          ...filters,
          {
            operator: operatorMap[operator],
            left,
            right: parseValue(operator, right.trim())
          }
        ];
      },
      []
    );

module.exports = {
  parseFilter
};
