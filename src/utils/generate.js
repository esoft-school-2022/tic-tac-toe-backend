/**
 * Генерирует рандомную строку.
 * @param length
 * @return {string}
 */
const randomString = (length = 8) => {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

  return Array
    .from({length})
    .reduce(
      (resultString) =>
        resultString + chars.charAt(Math.floor(Math.random() * chars.length)),
      ''
    );
};

/**
 * Рандомно выбирает из массива элемент.
 * @param {[]} array
 * @return {*}
 */
const randomFromArray = (array) => array[Math.floor((Math.random() * array.length))];

/**
 * Генерирует дату.
 * @param {Date} startDate
 * @param {Date} endDate
 * @param {int} startHour
 * @param {int} endHour
 * @return {Date}
 */
const randomDate = (startDate, endDate, startHour= 0, endHour= 24) => {
  const date = new Date(Number(startDate) + Math.random() * (endDate - startDate));

  date.setHours(startHour + Math.random() * (endHour - startHour) | 0);

  return date;
};

module.exports = {
  randomString,
  randomFromArray,
  randomDate
};
