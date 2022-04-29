/**
 * @param { import("knex").Knex } knex
 * @returns { Promise<void> }
 */
exports.up = async(knex) => {
  await knex.schema.createTable('users', (table) => {
    table
      .increments('id')
      .primary()
      .comment('Идентификатор');
    table
      .string('login', 256)
      .notNullable()
      .unique()
      .comment('Логин');
    table
      .string('password', 2048)
      .notNullable()
      .comment('Пароль');
    table
      .string('status', 64)
      .notNullable()
      .defaultTo('active')
      .comment('Статус');
    table
      .timestamp('created_at', {useTz: false})
      .notNullable()
      .defaultTo(knex.fn.now())
      .comment('Дата создания');
    table
      .timestamp('updated_at', {useTz: false})
      .nullable()
      .comment('Дата обновления');
    table.comment('Пользователи');
  });
  await knex.schema.createTable('games', (table) => {
    table
      .increments('id')
      .primary()
      .comment('Идентификатор');
    table
      .integer('size')
      .notNullable()
      .comment('Размер поля');
    table
      .integer('winner_number')
      .nullable()
      .comment('Номер победившего игрока');
    table
      .timestamp('created_at', {useTz: false})
      .notNullable()
      .defaultTo(knex.fn.now())
      .comment('Дата создания');
    table
      .timestamp('finished_at', {useTz: false})
      .nullable()
      .comment('Дата окончания');
    table
      .timestamp('deleted_at', {useTz: false})
      .nullable()
      .comment('Дата удаления');
    table.comment('Игры');
  });
  await knex.schema.createTable('players', (table) => {
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
      .integer('game_id')
      .notNullable()
      .references('id')
      .inTable('games')
      .comment('Идентификатор игры');
    table
      .integer('number')
      .notNullable()
      .comment('Номер игрока по порядку');
    table
      .unique(['user_id', 'game_id'])
      .unique(['game_id', 'number'])
      .comment('Игроки');
  });
  await knex.schema.createTable('moves', (table) => {
    table
      .increments('id')
      .primary()
      .comment('Идентификатор');
    table
      .integer('game_id')
      .notNullable()
      .comment('Идентификатор игры');
    table
      .integer('number')
      .notNullable()
      .comment('Номер хода по порядку');
    table
      .integer('position')
      .notNullable()
      .comment('Позиция на которую сделан ход');
    table
      .unique(['game_id', 'number'])
      .unique(['game_id', 'position'])
      .comment('Ходы');
  });
};

/**
 * @param { import("knex").Knex } knex
 * @returns { Promise<void> }
 */
exports.down = async(knex) => {
  await knex.schema.dropTable('moves');
  await knex.schema.dropTable('players');
  await knex.schema.dropTable('games');
  await knex.schema.dropTable('users');
};
