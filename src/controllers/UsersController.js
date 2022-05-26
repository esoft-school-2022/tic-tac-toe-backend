const {Controller} = require('../base');
const {NotFoundError} = require('../errors');
const {UsersDAL} = require('../data');

class UsersController extends Controller {
  constructor({db}) {
    super();

    this.users = new UsersDAL({db});
  }

  /**
   * Обрабатывает HTTP-запрос на получение пользователей.
   * @param {import('express').Request} req
   * @param {import('express').Response} res
   * @return {Promise<void>}
   */
  get = async(
    req,
    res
  ) => {
    const fields = req.query.fields?.split(',') || ['id', 'login', 'createdAt'];
    const filters = req.query.filters && this.parseFilter(req.query.filters) || [];
    const limit = Number(req.query.limit) >= 0 ? Number(req.query.limit) : 10;
    const offset = Number(req.query.offset) || 0;
    const {sort} = req.query;

    if (!filters.some(({left}) => left === 'status')) {
      filters.push({
        left: 'status',
        operator: '=',
        right: 'active'
      });
    }

    const users = await this.users.get(
      fields,
      filters,
      sort,
      limit,
      offset
    );

    res.json(users);
  }

  /**
   * Обрабатывает HTTP-запрос на создание пользователя.
   * @param {import('express').Request} req
   * @param {import('express').Response} res
   * @return {Promise<void>}
   */
  create = async(
    req,
    res
  ) => {
    const {login, password, status} = req.body;

    if (!login) {
      res.status(400).json({error: "Missing login!"});

      return;
    }

    if (!password) {
      res.status(400).json({error: "Missing password!"});

      return;
    }

    const user = await this.users.create(login, password, status);

    res.status(201).json(user);
  }

  /**
   * Обрабатывает HTTP-запрос на обновление пользователя.
   * @param {import('express').Request} req
   * @param {import('express').Response} res
   * @return {Promise<void>}
   */
  update = async(
    req,
    res
  ) => {
    const {userId} = req.params;

    if (Object.keys(req.body).some((key) => !['password', 'status'].includes(key))) {
      res.status(400).json({error: 'Unexpected param!'});
    }

    await this.users.update(userId, req.body);

    res.json({success: true});
  }

  /**
   * Обрабатывает HTTP-запрос на удаление пользователя.
   * @param {import('express').Request} req
   * @param {import('express').Response} res
   * @return {Promise<void>}
   */
  delete = async(
    req,
    res
  ) => {
    const {userId} = req.params;

    await this.users.delete(userId);

    res.json({success: true});
  };

  /**
   * Обрабатывает HTTP-запрос на получение пользователя.
   * @param {import('express').Request} req
   * @param {import('express').Response} res
   * @return {Promise<void>}
   */
  find = async(
    req,
    res
  ) => {
    const {userId} = req.params;
    const game = await this.users.find(userId);

    if (!game) {
      throw new NotFoundError('user', userId);
    }

    res.json(game);
  }
}

module.exports = UsersController;
