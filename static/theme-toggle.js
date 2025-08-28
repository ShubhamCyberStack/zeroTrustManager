document.addEventListener('DOMContentLoaded', function () {
    const themes = ['light', 'dark', 'autumn', 'rain', 'spring'];
    const themeIcons = {
        light: '☀️',
        dark: '🌙',
        autumn: '🍁',
        rain: '🌧️',
        spring: '🌈'
    };

    let savedTheme = localStorage.getItem('theme') || 'light';
    document.body.className = savedTheme;

    const toggleBtn = document.querySelector('.theme-toggle-btn');
    if (toggleBtn) toggleBtn.innerText = themeIcons[savedTheme];

    window.cycleTheme = function () {
        const currentTheme = document.body.className;
        let currentIndex = themes.indexOf(currentTheme);
        let nextIndex = (currentIndex + 1) % themes.length;
        let nextTheme = themes[nextIndex];
        document.body.className = nextTheme;
        localStorage.setItem('theme', nextTheme);
        if (toggleBtn) toggleBtn.innerText = themeIcons[nextTheme];
    };
});
