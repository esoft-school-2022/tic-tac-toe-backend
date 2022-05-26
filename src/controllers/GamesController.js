const {Controller} = require('../base');
const {GamesDAL} = require('../data');
const {NotFoundError} = require('../errors');

class GamesController extends Controller {
  constructor({db}) {
    super();

    this.games = new GamesDAL({db});
  }

  /**
   * Обрабатывает HTTP-запрос на получение игр.
   * @param {import('express').Request} req
   * @param {import('express').Response} res
   * @return {Promise<void>}
   */
  get = async(
    req,
    res
  ) => {
    const fields = req.query.fields?.split(',') || ['id', 'winner', 'createdAt', 'finishedAt'];
    const filters = req.query.filters && this.parseFilter(req.query.filters) || [];
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

    const games = await this.games.get(
      fields,
      filters,
      sort,
      limit,
      offset
    );

    res.json(games);
  }

  /**
   * Обрабатывает HTTP-запрос на создание игры.
   * @param {import('express').Request} req
   * @param {import('express').Response} res
   * @return {Promise<void>}
   */
  create = async(
    req,
    res
  ) => {
    const {userIds, size = 3} = req.body;
    const gameId = await this.games.create(userIds, size);

    res.status(201).send({gameId});
  }

  /**
   * Обрабатывает HTTP-запрос на обновление игры.
   * @param {import('express').Request} req
   * @param {import('express').Response} res
   * @return {Promise<void>}
   */
  update = async(
    req,
    res
  ) => {
    const {gameId} = req.params;
    const {winner} = req.body;

    await this.games.update(gameId, winner);

    res.json({success: true});
  }

  /**
   * Обрабатывает HTTP-запрос на удаление игры.
   * @param {import('express').Request} req
   * @param {import('express').Response} res
   * @return {Promise<void>}
   */
  delete = async(
    req,
    res
  ) => {
    const {gameId} = req.params;

    await this.games.delete(gameId);

    res.json({success: true});
  }

  /**
   * Обрабатывает HTTP-запрос на получение игры.
   * @param {import('express').Request} req
   * @param {import('express').Response} res
   * @return {Promise<void>}
   */
  find = async(
    req,
    res
  ) => {
    const {gameId} = req.params;

    const game = await this.games.find(gameId);

    if (!game) {
      throw new NotFoundError('game', gameId);
    }

    res.json(game);
  }
}

module.exports = GamesController;
