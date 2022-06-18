const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const {Controller} = require('../base');
const {UsersDAL} = require('../data');

class AuthController extends Controller {
  constructor({db, config, broker}) {
    super();

    this.authConfig = config.auth;
    this.cache = broker.pub;
    this.users = new UsersDAL({db});
  }

  /**
   * Создает JWT.
   * @param {object} user
   * @returns {Promise<string>}
   */
  sign = (user) => new Promise((resolve, reject) => {
    jwt.sign(
      {
        sub: {
          id: user.id,
          login: user.login,
          rights: user.rights,
          accesses: user.accesses
        }
      },
      this.authConfig.secret,
      this.authConfig.options,
      (error, result) => {
        if (error) {
          reject(error);
        } else {
          resolve(result);
        }
      }
    )
  })

  /**
   * Создает токен доступа.
   * @param {import('express').Request} req
   * @param {import('express').Response} res
   * @return {Promise<void>}
   */
  createToken = async(
    req,
    res
  ) => {
    const {login, password} = req.body;
    const [user] = await this.users.get(
      ['id', 'login', 'accesses', 'rights', 'password'],
      [
        {
          left: 'login',
          operator: '=',
          right: login
        },
        {
          left: 'status',
          operator: '=',
          right: 'active'
        }
      ]
    );

    if (!user) {
      res.status(400).json({error: 'Incorrect credentials'});

      return;
    }

    if (await bcrypt.compare(password, user.password)) {
      const token = await this.sign(user);
      const [, , refresh] = token.split('.');

      await this.cache.hSet(
        'tokens',
        {
          [refresh]: user.login
        }
      );

      res
        .status(201)
        .cookie('refresh-token', refresh, {signed: true})
        .json({token, refresh});
    } else {
      res.status(400).json({error: 'Incorrect credentials'});
    }
  }

  /**
   * Получает код пользователя из токена.
   * @param {import('express').Request} req
   * @param {import('express').Response} res
   * @return {void}
   */
  getResource = async(
    req,
    res
  ) => {
    const refresh = req.signedCookies['refresh-token'];

    if (!refresh) {
      res.sendStatus(401);

      return;
    }

    const refreshes = await this.cache.hGetAll('tokens');
    const login = refreshes[refresh];

    if (!login) {
      res.sendStatus(401);

      return;
    }

    const [user] = await this.users.get(
      ['id', 'login', 'accesses', 'rights', 'password'],
      [
        {
          left: 'login',
          operator: '=',
          right: login
        },
        {
          left: 'status',
          operator: '=',
          right: 'active'
        }
      ]
    );

    if (!user) {
      res.sendStatus(401);

      return;
    }

    const token = await this.sign(user);

    res.status(201).json({token});
  }

  /**
   * Проверяет токен.
   * @param payload
   * @param done
   * @return {Promise<*>}
   */
  verifyAuth = async(payload, done) => {
    try {
      if (payload.sub) {
        return done(null, payload.sub);
      } else {
        return done(null, false);
      }
    } catch(err) {
      return done(err, false);
    }
  }
}

module.exports = AuthController;
