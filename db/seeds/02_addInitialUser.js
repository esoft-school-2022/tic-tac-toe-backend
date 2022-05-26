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
 * @param {import("knex").Knex} knex
 * @returns {Promise<void>}
 */
exports.seed = async(knex) => {
  const password = randomString();
  const [{id: andreeffId}] = await knex
    .insert([
      {
        login: 'andreeff',
        password: await bcrypt.hash(password, 6)
      }
    ])
    .into('users')
    .returning('id');
  const roles = await knex
    .select(['id'])
    .from('roles');

  await knex
    .insert(
      roles
        .map(({id}) => ({
          user_id: andreeffId,
          role_id: id
        }))
    )
    .into('assigned_roles');

  console.log(`andreeff:${password}`);
}
