const {getGames, startGame, finishGame, cancelGame, findGame} = require('../models');
const {NotFoundError} = require('../errors');
const {parseFilter} = require('../utils');

/**
 * Обрабатывает HTTP-запрос на получение игр.
 * @type {import('express').RequestHandler}
 */
const getGamesController = async(
  req,
  res,
  next
) => {
  const fields = req.query.fields?.split(',') || ['id', 'winner', 'createdAt', 'finishedAt'];
  const filters = req.query.filters && parseFilter(req.query.filters) || [];

  if (!filters.some(({left}) => left === 'deletedAt')) {
    filters.push({
      left: 'deletedAt',
      operator: 'is',
      right: null
    });
  }

  try {
    const games = await getGames(
      fields,
      filters
    );

    res.json(games);
  } catch (err) {
    next(err);
  }
};

/**
 * Обрабатывает HTTP-запрос на создание игры.
 * @type {import('express').RequestHandler}
 */
const createGameController = async(
  req,
  res,
  next
) => {
  try {
    const {userIds, size = 3} = await req.json();
    const gameId = await startGame(userIds, size);

    res.status(201).send({gameId});
  } catch (err) {
    next(err);
  }
};

/**
 * Обрабатывает HTTP-запрос на обновление игры.
 * @type {import('express').RequestHandler}
 */
const updateGameController = async(
  req,
  res,
  next
) => {
  const {gameId} = req.params;
  const {winner} = await req.json();

  if (!gameId) {
    res.status(400).send({error: 'Game id expected'});

    return;
  }

  try {
    await finishGame(gameId, winner);

    res.json({success: true});
  } catch (err) {
    next(err);
  }
};

/**
 * Обрабатывает HTTP-запрос на удаление игры.
 * @type {import('express').RequestHandler}
 */
const deleteGameController = async(
  req,
  res,
  next
) => {
  const {gameId} = req.params;

  if (!gameId) {
    res.status(400).send({error: 'Game id expected'});

    return;
  }

  try {
    await cancelGame(gameId);

    res.json({success: true});
  } catch (err) {
    next(err);
  }
};

/**
 * Обрабатывает HTTP-запрос на получение игры.
 * @type {import('express').RequestHandler}
 */
const getGameController = async(
  req,
  res,
  next
) => {
  const {gameId} = req.params;

  if (!gameId) {
    res.status(400).send({error: 'Game id expected'});

    return;
  }

  try {
    const game = await findGame(gameId);

    if (!game) {
      next(new NotFoundError('game', gameId));
    }

    res.json(game);
  } catch (err) {
    next(err);
  }
}

module.exports = {
  createGameController,
  getGamesController,
  updateGameController,
  deleteGameController,
  getGameController
};
