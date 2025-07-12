// Animated dashboard widgets and chart for StackIt admin panel

document.addEventListener('DOMContentLoaded', function() {
    // Animate dashboard counters
    document.querySelectorAll('.dashboard-stat .stat-num').forEach(function(el) {
        let end = parseInt(el.getAttribute('data-value')) || 0;
        let currentText = el.textContent.trim();
        let currentValue = parseInt(currentText) || 0;
        
        // Only animate if there's a difference and the target is greater than 0
        if (end > 0 && end !== currentValue) {
            let cur = currentValue;
            let step = Math.ceil(Math.abs(end - currentValue) / 40);
            if (step === 0) step = 1;
            
            let interval = setInterval(function() {
                if (end > currentValue) {
                    cur += step;
                    if (cur >= end) {
                        cur = end;
                        clearInterval(interval);
                    }
                } else {
                    cur -= step;
                    if (cur <= end) {
                        cur = end;
                        clearInterval(interval);
                    }
                }
                el.textContent = cur;
            }, 20);
        }
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
