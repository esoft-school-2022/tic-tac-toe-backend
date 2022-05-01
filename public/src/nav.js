export default async(goTo) => {
  const responses = await Promise.all([
    fetch('/assets/svg/cross.svg'),
    fetch('/assets/svg/circle.svg')
  ]);
  const [cross, circle] = await Promise.all(responses.map((response) => response.text()));
  const template = document.createElement('template');

  template.innerHTML =
    `
      <nav class="nav">
        <div class="nav__icons">
          ${cross}
          ${circle}
          ${cross}
          ${circle}
        </div>
        <div class="nav__links">
          <a class="text nav__link" href="/game">Игровое поле</a>
          <a class="text nav__link" href="/statistics">Рейтинг</a>
          <a class="text nav__link" href="/active-players">Активные игроки</a>
          <a class="text nav__link" href="/history">История игр</a>
          <a class="text nav__link" href="/players">Список игроков</a>
        </div>
        <div class="nav__exit">
          <a>Выход</a>
        </div>
      </nav>
    `;

  for (const link of template.content.querySelector('.nav__links').children) {
    link.addEventListener(
      'click',
      (event) => {
        event.preventDefault();
        event.stopPropagation();

        goTo(event.target.getAttribute('href'));
      }
    );
  }

  for (const icon of template.content.querySelector('.nav__icons').children) {
    icon.classList.add('nav__icon');
  }

  return template.content;
};
