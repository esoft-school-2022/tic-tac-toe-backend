import nav from './nav.js';

export default async(goTo) => {
  const fields = ['winner', 'playerOne', 'playerTwo', 'createdAt', 'finishedAt'];
  const responses = await Promise.all([
    fetch('/assets/svg/cross.svg'),
    fetch('/assets/svg/circle.svg'),
    fetch(`/api/games?fields=${fields.join(',')}&with=players&limit=15&sort=finishedAt`)
  ]);
  const [cross, circle, games] = await Promise.all(responses.map(
    (response, idx) => idx !== 2 ? response.text() : response.json())
  );
  const circleTemplate = document.createElement('template');
  circleTemplate.innerHTML = circle;
  circleTemplate.content.firstElementChild.classList.add('history__player-two-icon');

  const crossTemplate = document.createElement('template');
  crossTemplate.innerHTML = cross;
  crossTemplate.content.firstElementChild.classList.add('history__player-one-icon');

  const template = document.createElement('template');

  template.innerHTML =
    `
      <main class="box container__content rating">
        <h1 class="text box__title history__title">История игр</h1>
        <table class="history__table table">
          <tr class="table__row">
            <th class="text table__cell table__cell_header">Игроки</th>
            <th class="text table__cell table__cell_header"></th>
            <th class="text table__cell table__cell_header"></th>
            <th class="text table__cell table__cell_header">Дата</th>
            <th class="text table__cell table__cell_header">Время игры</th>
          </tr>
          ${
            games 
              .map(
                ({winner, playerOne, playerTwo, createdAt, finishedAt}) =>
                  `
                    <tr class="table__cell">
                      <th class="text table__cell history__player-two">
                        ${circleTemplate.innerHTML}
                        ${playerTwo}
                        ${winner === 2 ?
                          '<img class="history__trophy" src="/assets/img/trophy.png" alt="Победитель">' :
                          ''
                        }
                      </th>
                      <th class="text table__cell history__versus">против</th>
                      <th class="text table__cell history__player-one">
                        ${crossTemplate.innerHTML}
                        ${playerOne}
                        ${winner === 1 ?
                          '<img class="history__trophy" src="/assets/img/trophy.png" alt="Победитель">' :
                          ''
                        }
                      </th>
                      <th class="text table__cell">${new Date(createdAt).toDateString().slice(4)}</th>
                      <th class="text table__cell">
                        ${
                          finishedAt ?
                            new Date(new Date(finishedAt) - new Date(createdAt)).toTimeString().slice(0, 8) :
                            new Date(createdAt).toTimeString().slice(0, 8)
                        }
                      </th>
                    </tr>
                  `
              )
              .join('')
          }
        </table>
      </main>
    `;

  template.content.prepend(await nav(goTo));
  template.content.querySelector('.nav__link[href="/history"]').classList.add('nav__link_active');

  return template.content;
};
