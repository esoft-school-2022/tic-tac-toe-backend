const routes = {
  '/statistics': {
    handler: () => import('./statistics.js'),
    title: 'Рейнтинг | Tic Tac Toe',
    styleSheet: './assets/css/statistics.css'
  },
  '/history': {
    handler: () => import('./history.js'),
    title: 'История игр | Tic Tac Toe',
    styleSheet: './assets/css/history.css'
  }
};

const handleRoute = async(location) => {
  const {handler, title, styleSheet} = routes[location];
  const {default: pageLoader} = await handler();
  const page = await pageLoader(async(newLocation) => {
    await handleRoute(newLocation);

    window.history.pushState({}, '', newLocation);
  });
  const cssLink = document.createElement('link');

  cssLink.rel = 'stylesheet';
  cssLink.type = 'text/css';
  cssLink.href = styleSheet;
  document.querySelector('.container').innerHTML = '';

  document.head.append(cssLink);
  document.head.querySelector('title').textContent = title;
  document.querySelector('.container').append(page);
};

window.onload = async() => {
  await handleRoute(window.location.pathname);
};
