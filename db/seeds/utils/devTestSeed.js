const bcrypt = require('bcrypt');

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

/**
 * @param {import("knex").Knex} knex
 * @returns {Promise<void>}
 */
exports.seed = async(knex) => {
  const userIds = await knex
    .insert(
      Array
        .from({length: 20})
        .map(() => {
          const login = randomString();
          const raw = randomString();
          const password = bcrypt.hashSync(raw, 6);

          console.log(`${login}:${raw}`);

          return {
            login,
            password
          }
        })
    )
    .into('users')
    .returning('id');
  const gameIds = await knex
    .into('games')
    .insert(
      Array
        .from({length: 20})
        .map(() => ({
          size: 3,
          winner: randomFromArray([null, 1, 2]),
          finished_at: randomDate(new Date(), new Date(2022, 5, 30)).toUTCString()
        }))
    )
    .returning('id');

  await knex('players')
    .insert(
      Array
        .from({length: 20})
        .map(() => {
          const {id: gameId} = randomFromArray(gameIds);
          const {id: firstPlayerId} = randomFromArray(userIds);
          const {id: secondPlayerId} = randomFromArray(userIds.filter(({id}) => id !== firstPlayerId));

          gameIds.splice(gameIds.findIndex(({id}) => id === gameId), 1);

          return [
            {
              game_id: gameId,
              user_id: firstPlayerId,
              number: 1
            },
            {
              game_id: gameId,
              user_id: secondPlayerId,
              number: 2
            }
          ];
        })
        .flat()
    );
};
