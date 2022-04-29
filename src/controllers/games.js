const {getGames, startGame, finishGame, cancelGame} = require('../models');
const {parseFilter} = require('../utils');

/**
 * Обрабатывает HTTP-запрос на получение игр.
 * @param {import('express').Request} req
 * @param {import('express').Response} res
 */
const getGamesController = async(
  req,
  res
) => {
  const fields = req.query.fields?.split(',') || ['id', 'winner', 'createdAt', 'finishedAt'];
  const filters = req.query.filter && parseFilter(req.query.filter) || [];

  if (!filters.some(({left}) => left === 'deletedAt')) {
    filters.push({
      left: 'deletedAt',
      operator: 'is',
      right: null
    });
  }

  const games = await getGames(
    fields,
    filters
  );

  res.json(games);
};

/**
 * Обрабатывает HTTP-запрос на создание игры.
 * @param {import('express').Request} req
 * @param {import('express').Response} res
 */
const createGameController = async(
  req,
  res
) => {
  const {userIds, size = 3} = await req.json();
  const gameId = await startGame(userIds, size);

  res.send({gameId});
};

/**
 * Обрабатывает HTTP-запрос на обновление игры.
 * @param {import('express').Request} req
 * @param {import('express').Response} res
 */
const updateGameController = async(
  req,
  res
) => {
  const {gameId, winner} = await req.json();

  if (!gameId) {
    res.status(400).send({error: 'Game id expected'});

    return;
  }

  try {
    await finishGame(gameId, winner);

    res.json({success: true});
  } catch (err) {
    res.status(400).json({error: err.message});
  }
};

/**
 * Обрабатывает HTTP-запрос на удаление игры.
 * @param {import('express').Request} req
 * @param {import('express').Response} res
 */
const deleteGameController = async(
  req,
  res
) => {
  const {gameId} = await req.json();

  if (!gameId) {
    res.status(400).send({error: 'Game id expected'});

    return;
  }

  try {
    await cancelGame(gameId);

    res.json({success: true});
  } catch (err) {
    res.status(400).json({error: err.message});
  }
};

module.exports = {
  createGameController,
  getGamesController,
  updateGameController,
  deleteGameController
};
