/**
 * @param {import("knex").Knex} knex
 * @returns {Promise<void>}
 */
exports.seed = async(knex) => {
  const [{id: adminId}, {id: publicId}] = await knex
    .insert([
      {
        name: 'admin',
      },
      {
        name: 'public',
      }
    ])
    .into('roles')
    .returning('id')
  const rights = await knex
    .insert([
      {
        name: 'users:read',
        entity: 'users',
        level: 1 << 0
      },
      {
        name: 'users:write',
        entity: 'users',
        level: 1 << 1
      },
      {
        name: 'users:block',
        entity: 'users',
        level: 1 << 2
      },
      {
        name: 'games:read',
        entity: 'games',
        level: 1 << 0
      },
      {
        name: 'games:create',
        entity: 'games',
        level: 1 << 1
      },
    ])
    .into('rights')
    .returning('id');
  const {id: gamesCreateId} = rights[rights.length - 1];
  await knex
    .insert([
      ...rights
        .map(({id}) => ({
          role_id: adminId,
          right_id: id
        })),
      {
        role_id: publicId,
        right_id: gamesCreateId
      }
    ])
    .into('available_rights');
}
