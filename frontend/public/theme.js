// Applying a stored theme from a module would paint the other one first: modules are deferred, so
// they run after the first paint. This is a classic script in the head, and it runs before the
// body exists, so a reload never flashes the wrong ground.
document.documentElement.style.colorScheme = localStorage.getItem("theme") || "light dark";
