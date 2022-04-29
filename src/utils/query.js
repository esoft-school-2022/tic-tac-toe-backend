const operatorMap = {
  eq: '=',
  neq: '<>',
  gt: '>',
  lt: '<',
  gte: '>=',
  lte: '<=',
  in: 'in',
  notin: 'not in',
  is: 'is',
  isnot: 'is not'
};

/**
 * Парсит фильтр
 * @param {string} filterQuery
 * @return {{operator: string, left: string, value: *}[]}
 */
const parseFilter = (filterQuery) => filterQuery
    .split(';')
    .reduce(
      (filters, rawFilter) => {
        const [left, operator, right] = rawFilter.trim().split(' ');

        return [
          ...filters,
          {
            operator: operatorMap[operator],
            left,
            right: right === 'null' ? null : right
          }
        ];
      },
      []
    );

module.exports = {
  parseFilter
};
