// Simple confetti effect for fun admin dashboard
function launchConfetti() {
  const colors = ['#ff4e50', '#f9d423', '#a1c4fd', '#fbc2eb', '#fdc094', '#ffb6b9', '#c2e9fb'];
  for (let i = 0; i < 42; i++) {
    const conf = document.createElement('div');
    conf.className = 'confetti';
    conf.style.left = Math.random() * 100 + 'vw';
    conf.style.background = colors[Math.floor(Math.random()*colors.length)];
    conf.style.animationDelay = (Math.random() * 0.6) + 's';
    conf.style.width = conf.style.height = (Math.random()*8+6) + 'px';
    document.body.appendChild(conf);
    setTimeout(() => conf.remove(), 1800);
  }
}
document.addEventListener('DOMContentLoaded', function() {
  launchConfetti();
});
