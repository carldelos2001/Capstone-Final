// Select all labels with the class 'header-menu-item'
const menuItems = document.querySelectorAll('.header-menu-item');

// Add a click event to each label
menuItems.forEach(item => {
  item.addEventListener('click', () => {
    // Remove 'selected' class from all items
    menuItems.forEach(label => label.classList.remove('selected'));

    // Add 'selected' class to the clicked item
    item.classList.add('selected');
  });
});
// Toggle mobile menu
const menuToggle = document.querySelector('.menu-toggle');
const navBar = document.querySelector('.nav_bar');

menuToggle.addEventListener('click', () => {
    navBar.classList.toggle('active');
    menuToggle.textContent = navBar.classList.contains('active') ? '✕' : '☰';
});

// Toggle dropdown menu
const dropdownToggle = document.querySelector('.dropdown-toggle');
const dropdownMenu = document.querySelector('.dropdown-menu');

dropdownToggle.addEventListener('click', (e) => {
    e.stopPropagation();
    dropdownMenu.style.display = dropdownMenu.style.display === 'block' ? 'none' : 'block';
});

// Close dropdown when clicking outside
document.addEventListener('click', () => {
    dropdownMenu.style.display = 'none';
});