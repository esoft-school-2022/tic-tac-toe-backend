const {Game} = require('./game');

/**
 * Класс, инкапсулирующий логику игры "Крестики-Нолики".
 */
class TicTacToe extends Game {
  /**
   * Размер поля.
   * @type {number}
   */
  #size;
  /**
   * Комбинации выигрышных позиций.
   * @type {number[][]}
   */
  #winPositions;
  /**
   * Игровое поле, где располагаются символы.
   * @type {?("X"|"O")[]}
   */
  #field;
  /**
   * Пара объектов игроков, у которых можно будет в последствии вытащить имя и символ.
   * @type {{info: *, symbol: "X"|"O"}[]}
   */
  #players;
  /**
   * Индекс текущего игрока
   * @type {number}
   */
  #currentPlayer;
  /**
   * Сделанные ходы.
   * @type {number[]}
   */
  #movesStack;
  /**
   * Выигрышная позиция.
   * @type {?number[]}
   */
  #winPosition;

  /**
   * @param {number} size
   * @param {*} playerOneInfo
   * @param {*} playerTwoInfo
   */
  constructor(size = 3, playerOneInfo = null, playerTwoInfo = null) {
    super();

    this.#players = [
      {info: playerOneInfo, symbol: "X"},
      {info: playerTwoInfo, symbol: "O"}
    ];

    this.restartWith(size);

    Object.freeze(this.#players[0]);
    Object.freeze(this.#players[1]);
  }

  /**
   * @inheritDoc
   */
  isWinner(player) {
    this.#winPosition = this.#winPositions.find(
      (winPosition) => winPosition.every(
        (cell) => this.#field[cell] === player.symbol
      )
    );

    return !!this.#winPosition;
  }

  /**
   * @inheritDoc
   */
  get isDraw() {
    return !this.#field.includes(null) && !this.#winPosition;
  }

  /**
   * @inheritDoc
   */
  makeMove(position, playerIdx) {
    if (this.isFinished) {
      throw new Error('Игра уже завершена');
    }

    if (this.#currentPlayer !== playerIdx) {
      throw new Error('Дождитесь хода другого игрока');
    }

    if (!this.isPossibleMove(position)) {
      throw new Error('Невозможный ход');
    }

    const currentPlayer = this.#players[this.#currentPlayer];

    this.#movesStack.push(position);
    this.#field[position] = this.#players[this.#currentPlayer].symbol;
    this.#currentPlayer = (this.#currentPlayer + 1) % 2;

    return currentPlayer;
  }

  /**
   * Отменяет последний ход.
   * Клетка снова становится пустой.
   * Ход убирается из стека.
   * Возвращает убранную позицию.
   * @returns {number}
   */
  undoLastMove() {
    if (!this.#movesStack.length) {
      throw new Error('Ходов ещё не было');
    }

    if (this.isFinished) {
      throw new Error('Игра уже завершена');
    }

    const lastMove = this.#movesStack.pop();

    this.#field[lastMove] = null;
    this.#currentPlayer = (this.#currentPlayer + 1) % 2;

    return lastMove;
  }

  /**
   * Подгружает информацию об игре.
   * @param {number[]} history
   * @returns
   */
  load(history) {
    if (this.#movesStack.length !== 0) {
      throw new Error('Игра уже началась');
    }

    try {
      history.forEach((position) => this.makeMove(position, this.#currentPlayer));
    } catch (err) {
      Array
        .from({length: this.#movesStack.length})
        .forEach(this.undoLastMove);

      throw err;
    }
  }

  /**
   * @inheritDoc
   */
  isPossibleMove(position) {
    return position >= 0 && position < this.#field.length && !this.#field[position];
  }

  /**
   * @inheritDoc
   */
  restartWith(size) {
    this.#size = size;
    this.#field = Array(this.#size * this.#size).fill(null);
    this.#winPositions = [
      // Строки
      Array
        .from({length: this.#size})
        .map((_, rowIdx) =>
          Array(this.#size)
            .fill(null)
            .map((__, colIdx) => this.#size * rowIdx + colIdx)
        ),
      // Столбцы
      Array
        .from({length: this.#size})
        .map((_, colIdx) =>
          Array(this.#size)
            .fill(null)
            .map((__, rowIdx) => this.#size * rowIdx + colIdx)
        ),
      // Главная диагональ
      [
        Array
          .from({length: this.#size})
          .map((_, idx) => idx * (this.#size + 1))
      ],
      // Побочная диагональ
      [
        Array
          .from({length: this.#size})
          .map((_, idx) => this.#size * (idx + 1) - idx - 1)
      ]
    ].flat();
    this.#movesStack = [];
    this.#currentPlayer = 0;
    this.#winPosition = null;
  }

  /**
   * @inheritDoc
   */
  get isFinished() {
    return !!this.#winPosition || this.isDraw;
  }

  /**
   * @inheritDoc
   */
  get players() {
    return [...this.#players];
  }

  /**
   * Получает информацию о текущем игроке.
   * @returns {{info: *, symbol: ("X"|"O")}}
   */
  get currentPlayer() {
    return this.#players[this.#currentPlayer];
  }

  /**
   * @inheritDoc
   */
  get winPosition() {
    return [...this.#winPosition];
  }

  /**
   * Получает состояние игрового поля.
   * @returns {?("X"|"O")[]}
   */
  get field() {
    return [...this.#field];
  }

  /**
   * @inheritDoc
   */
  get size() {
    return this.#size;
  }

  /**
   * Получает историю ходов.
   * @returns {number[]}
   */
  get moves() {
    return [...this.#movesStack];
  }
}

module.exports.TicTacToe = TicTacToe;
