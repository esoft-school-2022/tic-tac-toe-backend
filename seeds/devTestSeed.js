const {randomString, randomFromArray} = require("../src/utils");

/**
 * @param {import("knex").Knex} knex
 * @returns {Promise<void>}
 */
exports.seed = async(knex) => {
  await knex.raw('TRUNCATE TABLE users RESTART IDENTITY CASCADE');
  await knex.raw('TRUNCATE TABLE games RESTART IDENTITY CASCADE');

  const userIds = await knex
    .insert(
      Array
        .from({length: 20})
        .map(() => ({
          login: randomString(),
          password: randomString()
        }))
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
          winner: randomFromArray([null, 1, 2])
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
