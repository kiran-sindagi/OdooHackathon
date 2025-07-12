// Animated dashboard widgets and chart for StackIt admin panel

document.addEventListener('DOMContentLoaded', function() {
    // Animate dashboard counters
    document.querySelectorAll('.dashboard-stat .stat-num').forEach(function(el) {
        let end = parseInt(el.getAttribute('data-value')) || 0;
        let cur = 0;
        let step = Math.ceil(end / 40);
        let interval = setInterval(function() {
            cur += step;
            if (cur >= end) {
                cur = end;
                clearInterval(interval);
            }
            el.textContent = cur;
        }, 20);
    });
    // Simple animated bar chart (users/questions/answers)
    const chart = document.getElementById('admin-bar-chart');
    if (chart) {
        const bars = chart.querySelectorAll('.bar');
        bars.forEach(function(bar) {
            let val = parseInt(bar.getAttribute('data-value')) || 0;
            setTimeout(function() {
                bar.style.height = val + '%';
            }, 300);
        });
    }
});
