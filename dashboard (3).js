document.addEventListener('DOMContentLoaded', () => {
  const apiUrl = 'https://dansog-backend.onrender.com/api';
  const accessToken = sessionStorage.getItem('accessToken');
  const currentUser = JSON.parse(sessionStorage.getItem('currentUser'));

  const menuToggle = document.getElementById('menuToggle');
  const sideMenu = document.getElementById('sideMenu');
  const walletBalanceEl = document.getElementById('walletBalance');
  const actionSection = document.getElementById('actionSection');

  // Toggle side menu
  menuToggle.addEventListener('click', (e) => {
    e.stopPropagation();
    sideMenu.classList.toggle('-translate-x-full');
  });

  // Close side menu on outside click
  document.addEventListener('click', (e) => {
    if (!sideMenu.contains(e.target) && e.target !== menuToggle) {
      sideMenu.classList.add('-translate-x-full');
    }
  });

  // Handle menu item clicks
  document.querySelectorAll('[data-section]').forEach(item => {
    item.addEventListener('click', (e) => {
      const section = e.currentTarget.dataset.section;
      sideMenu.classList.add('-translate-x-full');
      handleMenuAction(section);
    });
  });

  // Load wallet balance
  async function loadDashboardStats() {
    try {
      const res = await fetch(`${apiUrl}/dashboard/stats`, {
        headers: { Authorization: `Bearer ${accessToken}` }
      });
      if (!res.ok) throw new Error("Stats error");
      const data = await res.json();
      walletBalanceEl.textContent = `${data.points_balance} pts`;
    } catch (err) {
      walletBalanceEl.textContent = "Error loading";
      console.error("Wallet error:", err);
    }
  }

  // Section handler
  async function handleMenuAction(section) {
    actionSection.innerHTML = '';

    if (!accessToken) {
      actionSection.innerHTML = `<p class="text-red-500">You must be logged in.</p>`;
      return;
    }

    switch (section) {
      case 'profile':
        await loadProfile();
        break;
      case 'history':
        await loadHistory();
        break;
      case 'redeem':
        await loadRedemptionForm();
        break;
      case 'transfer':
        loadTransferForm();
        break;
      case 'password':
        loadPasswordForm();
        break;
      case 'pin':
        loadPinForm();
        break;
      case 'logout':
        sessionStorage.clear();
        window.location.href = '/login';
        break;
      default:
        actionSection.innerHTML = `<p class="text-red-500">Unknown section selected.</p>`;
    }
  }

  async function loadProfile() {
    try {
      const res = await fetch(`${apiUrl}/users/me`, {
        headers: { Authorization: `Bearer ${accessToken}` }
      });
      const user = await res.json();
      actionSection.innerHTML = `
        <div class="bg-white p-6 rounded-lg shadow">
          <h3 class="text-lg font-bold mb-2">Your Profile</h3>
          <p><strong>Email:</strong> ${user.email}</p>
          <p><strong>Full Name:</strong> ${user.full_name || 'N/A'}</p>
          <p><strong>Username:</strong> ${user.username || 'N/A'}</p>
        </div>
      `;
    } catch {
      actionSection.innerHTML = 'Failed to load profile.';
    }
  }

  async function loadHistory() {
    try {
      const res = await fetch(`${apiUrl}/points/history`, {
        headers: { Authorization: `Bearer ${accessToken}` }
      });
      const data = await res.json();
      actionSection.innerHTML = `
        <div class="bg-white p-6 rounded-lg shadow">
          <h3 class="text-lg font-bold mb-2">Transfer History</h3>
          <ul class="space-y-1 text-sm">
            ${data.history.map(tx => `
              <li>${tx.amount} pts → ${tx.receiver_email} on ${new Date(tx.timestamp).toLocaleString()}</li>
            `).join('')}
          </ul>
        </div>
      `;
    } catch {
      actionSection.innerHTML = 'Failed to load history.';
    }
  }

  async function loadRedemptionForm() {
    try {
      const res = await fetch(`${apiUrl}/redemption/rates`, {
        headers: { Authorization: `Bearer ${accessToken}` }
      });
      const rates = await res.json();
      actionSection.innerHTML = `
        <div class="bg-white p-6 rounded-lg shadow">
          <h3 class="text-lg font-bold mb-4">Redeem Points</h3>
          <form id="redeemForm" class="space-y-4">
            <select name="type" class="w-full border p-2 rounded">
              <option value="btc">Bitcoin (${rates.btc_rate} pts/$)</option>
              <option value="giftcard">Gift Card (${rates.giftcard_rate} pts/$)</option>
            </select>
            <input name="amount" type="number" placeholder="Amount to redeem" class="w-full border p-2 rounded" required />
            <input name="destination" placeholder="Wallet or Email" class="w-full border p-2 rounded" required />
            <button class="bg-blue-600 text-white px-4 py-2 rounded">Redeem</button>
          </form>
        </div>
      `;
      document.getElementById('redeemForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const form = e.target;
        const payload = {
          type: form.type.value,
          amount: form.amount.value,
          destination: form.destination.value
        };
        try {
          const r = await fetch(`${apiUrl}/redemption/request`, {
            method: 'POST',
            headers: {
              Authorization: `Bearer ${accessToken}`,
              'Content-Type': 'application/json'
            },
            body: JSON.stringify(payload)
          });
          alert(r.ok ? "Redemption request submitted" : "Failed to redeem");
        } catch {
          alert("Error redeeming");
        }
      });
    } catch {
      actionSection.innerHTML = 'Failed to load rates.';
    }
  }

  function loadTransferForm() {
    actionSection.innerHTML = `
      <div class="bg-white p-6 rounded-lg shadow">
        <h3 class="text-lg font-bold mb-4">Transfer Points</h3>
        <form id="transferForm" class="space-y-4">
          <input name="receiver_email" placeholder="Receiver Email" class="w-full border p-2 rounded" required />
          <input name="amount" type="number" placeholder="Amount" class="w-full border p-2 rounded" required />
          <button class="bg-green-600 text-white px-4 py-2 rounded">Send</button>
        </form>
      </div>
    `;
    document.getElementById('transferForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      const form = e.target;
      const payload = {
        receiver_email: form.receiver_email.value,
        amount: parseInt(form.amount.value)
      };
      try {
        const res = await fetch(`${apiUrl}/points/transfer`, {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${accessToken}`,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify(payload)
        });
        alert(res.ok ? 'Transfer successful' : 'Transfer failed');
      } catch {
        alert('Transfer error');
      }
    });
  }

  function loadPasswordForm() {
    actionSection.innerHTML = `
      <div class="bg-white p-6 rounded-lg shadow">
        <h3 class="text-lg font-bold mb-4">Change Password</h3>
        <form id="passwordForm" class="space-y-4">
          <input type="password" name="old_password" placeholder="Old Password" class="w-full border p-2 rounded" required />
          <input type="password" name="new_password" placeholder="New Password" class="w-full border p-2 rounded" required />
          <button class="bg-yellow-500 text-white px-4 py-2 rounded">Change</button>
        </form>
      </div>
    `;
    document.getElementById('passwordForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      const form = e.target;
      const payload = {
        old_password: form.old_password.value,
        new_password: form.new_password.value
      };
      try {
        const res = await fetch(`${apiUrl}/auth/change-password`, {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${accessToken}`,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify(payload)
        });
        alert(res.ok ? "Password changed" : "Password change failed");
      } catch {
        alert("Password error");
      }
    });
  }

  function loadPinForm() {
    actionSection.innerHTML = `
      <div class="bg-white p-6 rounded-lg shadow">
        <h3 class="text-lg font-bold mb-4">Change PIN</h3>
        <form id="pinForm" class="space-y-4">
          <input type="password" name="old_pin" placeholder="Old PIN" class="w-full border p-2 rounded" required />
          <input type="password" name="new_pin" placeholder="New PIN" class="w-full border p-2 rounded" required />
          <button class="bg-purple-600 text-white px-4 py-2 rounded">Change</button>
        </form>
      </div>
    `;
    document.getElementById('pinForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      const form = e.target;
      const payload = {
        old_pin: form.old_pin.value,
        new_pin: form.new_pin.value
      };
      try {
        const res = await fetch(`${apiUrl}/auth/change-pin`, {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${accessToken}`,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify(payload)
        });
        alert(res.ok ? "PIN changed" : "PIN change failed");
      } catch {
        alert("PIN error");
      }
    });
  }

  loadDashboardStats();
});
