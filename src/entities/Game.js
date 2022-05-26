/**
 * Интерфейс игры.
 */
class Game {
  /**
   * Выполняет ход с проверкой на его возможность.
   * Бросает исключение, если ход невозможен.
   * Возвращает сходившего игрока.
   * @param {number} position
   * @param {number} playerIdx
   * @returns {{info: *, symbol: "X"|"O"}}
   */
  makeMove(position, playerIdx) {
    throw new Error("Not Implemented");
  }

  /**
   * Проверяет победил ли игрок по индексу, который передаётся,
   * с помощью обхода всех вариантов пока не встретится подходящий.
   * Возвращает true, если игрок победил, иначе false.
   * @param {{info: *, symbol: "X"|"O"}} playerIdx
   * @returns {boolean}
   */
  isWinner(playerIdx) {
    throw new Error("Not Implemented");
  }

  /**
   * Проверяет закончилась ли игра ничьей.
   * Игра закончилась ничьей, если заняты все клетки и никто не победил.
   * @returns {boolean}
   */
  get isDraw() {
    throw new Error("Not Implemented");
  }

  /**
   * Проверяет возможен ли ход.
   * Ход возможен если он не выходит за границы поля и если клетка ещё не занята.
   * @type {number} position
   * @returns {boolean}
   */
  isPossibleMove(position) {
    throw new Error("Not Implemented");
  }

  /**
   * Изменяет размер игры.
   * @param size
   * @returns {void}
   */
  restartWith(size) {
    throw new Error("Not Implemented");
  }

  /**
   * Проверяет начата ли игра.
   * @returns {boolean}
   */
  get isStarted() {
    throw new Error("Not Implemented");
  }

  /**
   * Проверяет завершена ли игра.
   * Игра завершена, если имеется победитель или ничья.
   * @returns {boolean}
   */
  get isFinished() {
    throw new Error("Not Implemented");
  }

  /**
   * Получает размер поля.
   * @returns {number}
   */
  get size() {
    throw new Error("Not Implemented");
  }

  /**
   * Получает информацию об игроках.
   * @returns {{info: *, symbol: ("X"|"O")}[]}
   */
  get players() {
    throw new Error("Not Implemented");
  }

  /**
   * Получает позицию победы.
   * @returns {?number[]}
   */
  get winPosition() {
    throw new Error("Not Implemented");
  }
}

module.exports.Game = Game;
