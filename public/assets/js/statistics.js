import nav from './nav.js';

export default async(goTo) => {
  const response = await fetch('/api/statistics?limit=15');
  const {statistics} = await response.json();
  const template = document.createElement('template');

  template.innerHTML =
    `
      <main class="box container__content rating">
        <h1 class="text rating__title">Рейтинг игроков</h1>
        <table class="rating__table">
          <tr class="rating__row rating__row_header">
            <th class="text rating__cell rating__cell_header">Логин</th>
            <th class="text rating__cell rating__cell_header">Всего игр</th>
            <th class="text rating__cell rating__cell_header">Победы</th>
            <th class="text rating__cell rating__cell_header">Проигрыши</th>
            <th class="text rating__cell rating__cell_header">Процент побед</th>
          </tr>
          ${
            statistics
              .map(
                ({login, total, wins, loses, winRate}) =>
                  `
                    <tr class="rating_row">
                      <th class="text rating__cell rating__cell_login">${login}</th>
                      <th class="text rating__cell">${total}</th>
                      <th class="text rating__cell rating__cell_wins">${wins}</th>
                      <th class="text rating__cell rating__cell_loses">${loses}</th>
                      <th class="text rating__cell rating__cell">${Math.round(winRate * 100)}%</th>
                    </tr>
                  `
              )
              .join('')
          }
        </table>
      </main>
    `;

  template.content.prepend(await nav(goTo));
  template.content.querySelector('.nav__link[href="/statistics"]').classList.add('nav__link_active');

  return template.content;
};
