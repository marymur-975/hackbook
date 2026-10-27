document.addEventListener("DOMContentLoaded", function () {
  // Находим все элементы списка задач (там, где наши чекбоксы)
  const taskItems = document.querySelectorAll(".task-list-item");

  taskItems.forEach((item, index) => {
    const checkbox = item.querySelector('input[type="checkbox"]');
    if (!checkbox) return;

    // Создаем уникальный ключ для этой страницы
    const key = "hackbook-progress-" + window.location.pathname + "-" + index;

    // Восстанавливаем состояние
    if (localStorage.getItem(key) === "true") {
      checkbox.checked = true;
      item.style.opacity = "0.6"; // Визуально показываем, что выполнено
      item.style.textDecoration = "line-through";
    }

    // Перехватываем клик на всю строку с текстом
    item.style.cursor = "pointer";
    item.addEventListener("click", function (e) {
      // Если кликнули по самому чекбоксу или по тексту
      if (
        e.target.tagName === "INPUT" ||
        e.target.tagName === "LABEL" ||
        e.target.tagName === "P"
      ) {
        checkbox.checked = !checkbox.checked;
        const isChecked = checkbox.checked;

        // Сохраняем
        localStorage.setItem(key, isChecked);

        // Меняем стиль
        if (isChecked) {
          item.style.opacity = "0.6";
          item.style.textDecoration = "line-through";
        } else {
          item.style.opacity = "1";
          item.style.textDecoration = "none";
        }
      }
    });
  });
});
