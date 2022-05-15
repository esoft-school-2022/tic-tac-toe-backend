const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const {Controller} = require('../base');
const {UsersDAL} = require('../models');

class AuthController extends Controller {
  constructor({db, config}) {
    super();

    this.authConfig = config.auth;
    this.users = new UsersDAL({db});
  }

  /**
   * Создает токен доступа.
   * @param {import('express').Request} req
   * @param {import('express').Response} res
   * @param {import('express').NextFunction} next
   * @return {Promise<void>}
   */
  createToken = async(
    req,
    res,
    next
  ) => {
    const {login, password} = req.body;
    const [user] = await this.users.get(
      ['id', 'password'],
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
      jwt.sign(
        {sub: user.id},
        this.authConfig.secret,
        this.authConfig.options,
        (error, token) => {
          if (error) {
            next(error);
          } else {
            res
              .status(201)
              .json({token});
          }
        }
      );
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
  getResource = (
    req,
    res
  ) => {
    res.status(200).json(req.user);
  }

  /**
   * Проверяет токен.
   * @param payload
   * @param done
   * @return {Promise<*>}
   */
  verifyAuth = async(payload, done) => {
    try {
      const user = await this.users.find(payload.sub);

      if (user) {
        return done(null, {...user, password: undefined});
      } else {
        return done(null, false);
      }
    } catch(err) {
      return done(err, false);
    }
  }
}

module.exports = AuthController;
