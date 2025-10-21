// plans.js - GoldenSpaceAI Golden Packages with NOWPayments ($15 minimum)
const GOLDEN_PACKAGES = {
  60: { priceUSD: 15, description: "Standard Pack", popular: true },
  100: { priceUSD: 20, description: "Pro Pack", popular: false },
  200: { priceUSD: 40, description: "Ultimate Pack", popular: false }
};

// Initialize the page
document.addEventListener('DOMContentLoaded', async function() {
  document.getElementById('yr').textContent = new Date().getFullYear();
  await loadUserBalance();
  renderGoldenPackages();
});

// Load user's current Golden balance
async function loadUserBalance() {
  try {
    const response = await fetch('/api/me', { credentials: 'include' });
    const data = await response.json();
    
    if (data.loggedIn) {
      document.getElementById('userBalanceSection').style.display = 'block';
      document.getElementById('currentBalance').textContent = `${data.balance || 0}G`;
    }
  } catch (error) {
    console.error('Error loading user balance:', error);
  }
}

// Render Golden packages
function renderGoldenPackages() {
  const container = document.getElementById('packagesContainer');
  
  container.innerHTML = Object.entries(GOLDEN_PACKAGES)
    .map(([amount, info]) => {
      const valuePerGolden = (info.priceUSD / amount).toFixed(3);
      const savings = amount >= 60 ? `Save $${(0.25 * amount - info.priceUSD).toFixed(2)}` : '';
      
      return `
        <div class="package-card ${info.popular ? 'popular' : ''}">
          ${info.popular ? '<div class="popular-badge">BEST VALUE</div>' : ''}
          <div class="golden-amount">${amount}G</div>
          <div class="price">$${info.priceUSD}</div>
          <div class="value">$${valuePerGolden} per Golden • ${savings}</div>
          <div style="color:var(--muted); font-size:14px; margin-bottom:15px;">${info.description}</div>
          <button class="btn gold" onclick="buyGolden(${amount})" id="buyBtn${amount}">
            🪙 Buy ${amount} Golden - $${info.priceUSD}
          </button>
        </div>
      `;
    }).join('');
}

// Buy Golden package
async function buyGolden(packageSize) {
  const button = document.getElementById(`buyBtn${packageSize}`);
  const originalText = button.textContent;
  
  try {
    // Show loading state
    button.classList.add('loading');
    button.textContent = 'Creating Payment';
    
    // Check if user is logged in
    const meResponse = await fetch('/api/me', { credentials: 'include' });
    const meData = await meResponse.json();
    
    if (!meData.loggedIn) {
      if (confirm('You need to log in to purchase Golden tokens. Go to login page?')) {
        window.location.href = '/login-signup.html';
      }
      return;
    }

    // Create payment with NOWPayments
    const response = await fetch('/api/nowpayments/create-golden', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ packageSize: parseInt(packageSize) }),
      credentials: 'include'
    });
    
    const data = await response.json();
    
    if (data.success) {
      // Redirect to NOWPayments checkout
      console.log('Redirecting to NOWPayments:', data.invoiceUrl);
      window.location.href = data.invoiceUrl;
    } else {
      alert('Error: ' + (data.error || 'Failed to create payment'));
      console.error('Payment creation failed:', data);
    }
  } catch (error) {
    console.error('Buy Golden error:', error);
    alert('Network error: ' + error.message);
  } finally {
    // Reset button
    button.classList.remove('loading');
    button.textContent = originalText;
  }
}

// Check payment status (for when users return to the page)
async function checkPendingPayments() {
  try {
    const balanceResponse = await fetch('/api/golden-balance', { credentials: 'include' });
    const balanceData = await balanceResponse.json();
    
    if (balanceData.loggedIn) {
      document.getElementById('currentBalance').textContent = `${balanceData.balance || 0}G`;
    }
  } catch (error) {
    console.error('Error checking payments:', error);
  }
}

// Check for payment success in URL parameters
function checkUrlForPaymentSuccess() {
  const urlParams = new URLSearchParams(window.location.search);
  const paymentStatus = urlParams.get('payment');
  
  if (paymentStatus === 'success') {
    alert('✅ Payment successful! Your Golden tokens have been added to your account.');
    window.history.replaceState({}, document.title, window.location.pathname);
    loadUserBalance();
  } else if (paymentStatus === 'cancelled') {
    alert('ℹ️ Payment was cancelled. You can try again anytime.');
    window.history.replaceState({}, document.title, window.location.pathname);
  }
}

// Check for payment status when page loads
checkUrlForPaymentSuccess();

// Periodically check balance updates
setInterval(loadUserBalance, 30000);
