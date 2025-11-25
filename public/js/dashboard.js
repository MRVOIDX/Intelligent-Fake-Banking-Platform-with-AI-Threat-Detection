document.addEventListener('DOMContentLoaded', async function() {
    const logoutBtn = document.getElementById('logoutBtn');
    const userName = document.getElementById('userName');
    const greeting = document.getElementById('greeting');
    const currentDate = document.getElementById('currentDate');
    const totalBalance = document.getElementById('totalBalance');
    const availableBalance = document.getElementById('availableBalance');
    const savingsBalance = document.getElementById('savingsBalance');
    const cardNumber = document.getElementById('cardNumber');
    const cardHolder = document.getElementById('cardHolder');
    const transactionsList = document.getElementById('transactionsList');

    async function checkAuth() {
        try {
            const token = localStorage.getItem('authToken');
            if (!token) {
                window.location.href = '/login.html';
                return false;
            }

            const response = await fetch('/api/check-auth', {
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });
            const data = await response.json();

            if (!data.authenticated) {
                localStorage.removeItem('authToken');
                window.location.href = '/login.html';
                return false;
            }

            return data.user;
        } catch (error) {
            console.error('Auth check error:', error);
            localStorage.removeItem('authToken');
            window.location.href = '/login.html';
            return false;
        }
    }

    async function loadAccountData() {
        try {
            const token = localStorage.getItem('authToken');
            const response = await fetch('/api/account', {
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });
            const data = await response.json();

            if (response.ok) {
                const user = data.user;
                const account = data.account;

                userName.textContent = user.name;
                greeting.textContent = `Welcome back, ${user.name.split(' ')[0]}!`;
                cardHolder.textContent = user.name.toUpperCase();

                totalBalance.textContent = `$${account.balance.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
                availableBalance.textContent = `$${account.available.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
                savingsBalance.textContent = `$${account.savings.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
                cardNumber.textContent = `•••• •••• •••• ${account.card_number}`;

                displayTransactions(account.transactions);
            } else {
                window.location.href = '/login.html';
            }
        } catch (error) {
            console.error('Load account error:', error);
            window.location.href = '/login.html';
        }
    }

    function displayTransactions(transactions) {
        if (!transactions || transactions.length === 0) {
            transactionsList.innerHTML = `
                <div class="transaction-item" data-testid="transaction-empty">
                    <div style="width: 100%; text-align: center; padding: 2rem; color: var(--text-secondary);">
                        No transactions yet
                    </div>
                </div>
            `;
            return;
        }

        transactionsList.innerHTML = transactions.map((transaction, index) => {
            let icon = 'CARD';
            let title = 'Transaction';
            let description = '';
            let amountClass = transaction.amount >= 0 ? 'positive' : 'negative';
            let amountText = transaction.amount >= 0 ? `+$${Math.abs(transaction.amount).toFixed(2)}` : `-$${Math.abs(transaction.amount).toFixed(2)}`;

            if (transaction.type === 'sent') {
                icon = 'OUT';
                title = 'Money Sent';
                description = `to ${transaction.to}`;
            } else if (transaction.type === 'received') {
                icon = 'IN';
                title = 'Payment Received';
                description = `from ${transaction.from}`;
            } else if (transaction.type === 'purchase') {
                icon = 'CARD';
                title = 'Purchase';
                description = `at ${transaction.at}`;
            }

            return `
                <div class="transaction-item" data-testid="transaction-${index}">
                    <div class="transaction-icon">${icon}</div>
                    <div class="transaction-details">
                        <div class="transaction-title">${title}</div>
                        <div class="transaction-description">${description}</div>
                    </div>
                    <div class="transaction-amount ${amountClass}" data-testid="amount-${index}">${amountText}</div>
                </div>
            `;
        }).join('');
    }

    const date = new Date();
    const options = { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' };
    currentDate.textContent = date.toLocaleDateString('en-US', options);

    const user = await checkAuth();
    if (user) {
        await loadAccountData();
    }

    if (logoutBtn) {
        logoutBtn.addEventListener('click', async function() {
            try {
                const token = localStorage.getItem('authToken');
                await fetch('/api/logout', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${token}`
                    }
                });

                localStorage.removeItem('authToken');
                window.location.href = '/index.html';
            } catch (error) {
                console.error('Logout error:', error);
                localStorage.removeItem('authToken');
                window.location.href = '/index.html';
            }
        });
    }
});
