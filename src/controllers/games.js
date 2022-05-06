const {getGames, startGame, finishGame, cancelGame, findGame} = require('../models');
const {NotFoundError} = require('../errors');
const {parseFilter} = require('../utils');

/**
 * Обрабатывает HTTP-запрос на получение игр.
 * @param {import('express').Request} req
 * @param {import('express').Response} res
 * @return {Promise<void>}
 */
const getGamesController = async(
  req,
  res
) => {
  const fields = req.query.fields?.split(',') || ['id', 'winner', 'createdAt', 'finishedAt'];
  const filters = req.query.filters && parseFilter(req.query.filters) || [];
  const limit = Number(req.query.limit) >= 0 ? Number(req.query.limit) : 10;
  const offset = Number(req.query.offset) || 0;
  const {sort} = req.query;

  if (!filters.some(({left}) => left === 'deletedAt')) {
    filters.push({
      left: 'deletedAt',
      operator: 'is',
      right: null
    });
  }

  const games = await getGames(
    fields,
    filters,
    sort,
    limit,
    offset
  );

  res.json(games);
};

/**
 * Обрабатывает HTTP-запрос на создание игры.
 * @param {import('express').Request} req
 * @param {import('express').Response} res
 * @return {Promise<void>}
 */
const createGameController = async(
  req,
  res
) => {
  const {userIds, size = 3} = req.body;
  const gameId = await startGame(userIds, size);

  res.status(201).send({gameId});
};

/**
 * Обрабатывает HTTP-запрос на обновление игры.
 * @param {import('express').Request} req
 * @param {import('express').Response} res
 * @return {Promise<void>}
 */
const updateGameController = async(
  req,
  res
) => {
  const {gameId} = req.params;
  const {winner} = req.body;

  await finishGame(gameId, winner);

  res.json({success: true});
};

/**
 * Обрабатывает HTTP-запрос на удаление игры.
 * @param {import('express').Request} req
 * @param {import('express').Response} res
 * @return {Promise<void>}
 */
const deleteGameController = async(
  req,
  res
) => {
  const {gameId} = req.params;

  await cancelGame(gameId);

  res.json({success: true});
};

/**
 * Обрабатывает HTTP-запрос на получение игры.
 * @param {import('express').Request} req
 * @param {import('express').Response} res
 * @return {Promise<void>}
 */
const getGameController = async(
  req,
  res
) => {
  const {gameId} = req.params;

  const game = await findGame(gameId);

  if (!game) {
    throw new NotFoundError('game', gameId);
  }

  res.json(game);
}

module.exports = {
  createGameController,
  getGamesController,
  updateGameController,
  deleteGameController,
  getGameController
};
