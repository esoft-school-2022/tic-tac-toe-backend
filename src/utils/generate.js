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

module.exports = {
  randomString,
  randomFromArray
};
