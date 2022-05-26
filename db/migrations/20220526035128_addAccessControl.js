/**
 * @param { import("knex").Knex } knex
 * @returns { Promise<void> }
 */
exports.up = async(knex) => {
  await knex.schema.createTable('accesses', (table) => {
    table
      .increments('id')
      .primary()
      .comment('Идентификатор');
    table
      .integer('user_id')
      .notNullable()
      .references('id')
      .inTable('users')
      .comment('Идентификатор пользователя');
    table
      .string('entity')
      .notNullable()
      .comment('Сущность');
    table
      .integer('entity_id')
      .notNullable()
      .comment('Идентификатор сущности');
    table
      .integer('level')
      .notNullable()
      .comment('Уровень доступа');
    table
      .unique(['user_id', 'entity', 'entity_id'])
      .comment('Доступы');
  });
  await knex.schema.createTable('rights', (table) => {
    table
      .increments('id')
      .primary()
      .comment('Идентификатор');
    table
      .string('name')
      .notNullable()
      .comment('Мнемоника права');
    table
      .string('entity')
      .notNullable()
      .comment('Сущность');
    table
      .integer('level')
      .notNullable()
      .comment('Уровень доступа');
    table
      .comment('Права');
  });
  await knex.schema.createTable('roles', (table) => {
    table
      .increments('id')
      .primary()
      .comment('Идентификатор');
    table
      .string('name')
      .notNullable()
      .comment('Мнемоника роли');
    table
      .boolean('active')
      .notNullable()
      .defaultTo(true)
      .comment('Активность');
    table
      .timestamp('created_at', {useTz: false})
      .notNullable()
      .defaultTo(knex.fn.now())
      .comment('Дата создания');
    table
      .comment('Роли');
  });
  await knex.schema.createTable('available_rights', (table) => {
    table
      .increments('id')
      .primary()
      .comment('Идентификатор');
    table
      .integer('role_id')
      .notNullable()
      .references('id')
      .inTable('roles')
      .comment('Идентификатор роли');
    table
      .integer('right_id')
      .notNullable()
      .references('id')
      .inTable('rights')
      .comment('Идентификатор права');
    table
      .unique(['role_id', 'right_id'])
      .comment('Доступные права ролей');
  });
  await knex.schema.createTable('assigned_roles', (table) => {
    table
      .increments('id')
      .primary()
      .comment('Идентификатор');
    table
      .integer('user_id')
      .notNullable()
      .references('id')
      .inTable('users')
      .comment('Идентификатор пользователя');
    table
      .integer('role_id')
      .notNullable()
      .references('id')
      .inTable('roles')
      .comment('Идентификатор роли');
    table
      .unique(['role_id', 'user_id'])
      .comment('Назначенные роли пользователям');
  });
};

/**
 * @param { import("knex").Knex } knex
 * @returns { Promise<void> }
 */
exports.down = async(knex) => {
  await knex.schema.dropTable('assigned_roles');
  await knex.schema.dropTable('available_rights');
  await knex.schema.dropTable('roles');
  await knex.schema.dropTable('rights');
  await knex.schema.dropTable('accesses');
};
