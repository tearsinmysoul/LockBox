// Ждем полной загрузки DOM перед выполнением скрипта
document.addEventListener('DOMContentLoaded', () => {
  console.log('Приложение загружено и готово к работе!');

  const button = document.getElementById('actionBtn');

  if (button) {
    button.addEventListener('click', () => {
      alert('Кнопка была нажата! JS работает корректно.');
    });
  }
});
