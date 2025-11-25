document.addEventListener('DOMContentLoaded', async function() {
    const sidebar = document.getElementById('sidebar');
    const navItems = document.querySelectorAll('.nav-item');
    const pageContainer = document.getElementById('pageContainer');
    const loadingState = document.getElementById('loadingState');
    const logoutBtn = document.getElementById('logoutBtn');
    const userName = document.getElementById('userName');
    const userAvatar = document.getElementById('userAvatar');
    
    let currentUser = null;
    let currentUsers = [];

    // Check authentication
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

            if (!data.authenticated || !data.user.isAdmin) {
                localStorage.removeItem('authToken');
                window.location.href = '/login.html';
                return false;
            }

            currentUser = data.user;
            return data.user;
        } catch (error) {
            console.error('Auth check error:', error);
            localStorage.removeItem('authToken');
            window.location.href = '/login.html';
            return false;
        }
    }

    // Initialize
    const user = await checkAuth();
    if (!user) return;

    userName.textContent = user.name;
    userAvatar.textContent = user.name.charAt(0).toUpperCase();
    loadingState.style.display = 'none';

    // Navigation
    navItems.forEach(item => {
        item.addEventListener('click', function() {
            navItems.forEach(nav => nav.classList.remove('active'));
            this.classList.add('active');
            
            const page = this.getAttribute('data-page');
            loadPage(page);
        });
    });

    // Logout
    logoutBtn.addEventListener('click', async function() {
        try {
            const token = localStorage.getItem('authToken');
            await fetch('/api/logout', {
                method: 'POST',
                headers: {
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

    // Load initial page
    loadPage('dashboard');

    // Page loader
    async function loadPage(page) {
        switch(page) {
            case 'dashboard':
                await loadDashboardPage();
                break;
            case 'users':
                await loadUsersPage();
                break;
            case 'security':
                await loadSecurityPage();
                break;
            case 'cyberguard':
                await loadCyberGuardPage();
                break;
        }
    }

    // ========== DASHBOARD PAGE ==========
    async function loadDashboardPage() {
        try {
            const token = localStorage.getItem('authToken');
            const [usersRes, statsRes] = await Promise.all([
                fetch('/api/admin/users', {
                    headers: { 'Authorization': `Bearer ${token}` }
                }),
                fetch('/api/admin/security-stats', {
                    headers: { 'Authorization': `Bearer ${token}` }
                })
            ]);

            const usersData = await usersRes.json();
            const statsData = await statsRes.json();

            const totalUsers = usersData.users.length;
            const activeUsers = usersData.users.filter(u => !u.blocked && !u.isAdmin).length;
            
            pageContainer.innerHTML = `
                <div class="page-header">
                    <h1 class="page-title" data-testid="text-page-title">Dashboard Overview</h1>
                    <p class="page-subtitle" data-testid="text-page-subtitle">Real-time statistics and system health</p>
                </div>

                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 1.5rem; margin-bottom: 2rem;">
                    ${createStatCard('Total Users', totalUsers, '👥', 'var(--primary-blue)', 'stat-total-users')}
                    ${createStatCard('Active Users', activeUsers, '✅', '#10b981', 'stat-active-users')}
                    ${createStatCard('Blocked Users', statsData.blocked_users_count, '🚫', '#f59e0b', 'stat-blocked-users')}
                    ${createStatCard('Failed Logins', statsData.failed_logins, '⚠️', '#ef4444', 'stat-failed-logins')}
                    ${createStatCard('Brute Force Attempts', statsData.brute_force_attempts, '🔥', '#dc2626', 'stat-brute-force')}
                    ${createStatCard('SQL Injections', statsData.sql_injection_attempts, '💉', '#8b5cf6', 'stat-sql-injection')}
                </div>

                <div style="background: white; padding: 2rem; border-radius: 16px; box-shadow: 0 4px 20px rgba(0, 0, 0, 0.08);">
                    <h2 style="font-size: 1.5rem; font-weight: 700; margin-bottom: 1rem; color: var(--dark-gray);" data-testid="text-quick-actions">Quick Actions</h2>
                    <div style="display: flex; gap: 1rem; flex-wrap: wrap;">
                        <button onclick="navigateTo('users')" class="action-btn" data-testid="button-manage-users">
                            👥 Manage Users
                        </button>
                        <button onclick="navigateTo('security')" class="action-btn" data-testid="button-view-logs">
                            🔒 View Security Logs
                        </button>
                        <button onclick="navigateTo('cyberguard')" class="action-btn" data-testid="button-cyberguard">
                            🛡️ CyberGuardAI
                        </button>
                    </div>
                </div>

                <style>
                    .action-btn {
                        background: var(--primary-blue);
                        color: white;
                        border: none;
                        padding: 0.875rem 1.5rem;
                        border-radius: 8px;
                        font-weight: 600;
                        cursor: pointer;
                        transition: var(--transition);
                        font-size: 1rem;
                    }
                    .action-btn:hover {
                        background: var(--dark-blue);
                        transform: translateY(-2px);
                    }
                </style>
            `;
        } catch (error) {
            console.error('Error loading dashboard:', error);
            pageContainer.innerHTML = '<div style="text-align: center; padding: 3rem; color: #ef4444;">Failed to load dashboard</div>';
        }
    }

    function createStatCard(title, value, icon, color, testId) {
        return `
            <div style="background: white; padding: 1.5rem; border-radius: 12px; box-shadow: 0 2px 10px rgba(0, 0, 0, 0.08);" data-testid="card-${testId}">
                <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 0.75rem;">
                    <div style="font-size: 0.9rem; color: var(--text-secondary); font-weight: 500;">${title}</div>
                    <div style="font-size: 1.5rem;">${icon}</div>
                </div>
                <div style="font-size: 2rem; font-weight: 700; color: ${color};" data-testid="value-${testId}">${value}</div>
            </div>
        `;
    }

    window.navigateTo = function(page) {
        navItems.forEach(nav => {
            if (nav.getAttribute('data-page') === page) {
                nav.click();
            }
        });
    };

    // ========== USERS PAGE ==========
    async function loadUsersPage() {
        try {
            const token = localStorage.getItem('authToken');
            const response = await fetch('/api/admin/users', {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            const data = await response.json();
            currentUsers = data.users;

            pageContainer.innerHTML = `
                <div class="page-header">
                    <h1 class="page-title" data-testid="text-page-title">User Management</h1>
                    <p class="page-subtitle" data-testid="text-page-subtitle">Manage user accounts, add funds, and control access</p>
                </div>

                <div style="background: white; padding: 2rem; border-radius: 16px; box-shadow: 0 4px 20px rgba(0, 0, 0, 0.08);">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5rem;">
                        <h2 style="font-size: 1.5rem; font-weight: 700; color: var(--dark-gray);" data-testid="text-users-title">All Users</h2>
                        <div style="background: var(--light-blue); color: var(--primary-blue); padding: 0.5rem 1rem; border-radius: 8px; font-weight: 600;" data-testid="text-users-count">
                            ${currentUsers.length} Users
                        </div>
                    </div>
                    
                    <div style="overflow-x: auto;">
                        <table style="width: 100%; border-collapse: collapse;" data-testid="table-users">
                            <thead style="background: var(--light-gray);">
                                <tr>
                                    <th style="text-align: left; padding: 1rem; font-weight: 600; color: var(--dark-gray);">User</th>
                                    <th style="text-align: left; padding: 1rem; font-weight: 600; color: var(--dark-gray);">Balance</th>
                                    <th style="text-align: left; padding: 1rem; font-weight: 600; color: var(--dark-gray);">Status</th>
                                    <th style="text-align: left; padding: 1rem; font-weight: 600; color: var(--dark-gray);">Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${currentUsers.map((user, index) => `
                                    <tr style="border-bottom: 1px solid var(--border-color);" data-testid="row-user-${index}">
                                        <td style="padding: 1rem;">
                                            <div style="font-weight: 600; color: var(--dark-gray);" data-testid="text-user-name-${index}">${user.name}</div>
                                            <div style="color: var(--text-secondary); font-size: 0.9rem;" data-testid="text-user-email-${index}">${user.email}</div>
                                        </td>
                                        <td style="padding: 1rem;">
                                            <div style="font-weight: 700; color: var(--primary-blue); font-size: 1.1rem;" data-testid="text-user-balance-${index}">
                                                ${user.account ? '$' + user.account.balance.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 }) : 'N/A'}
                                            </div>
                                        </td>
                                        <td style="padding: 1rem;">
                                            ${user.isAdmin 
                                                ? '<span style="background: #dbeafe; color: #3b82f6; padding: 0.375rem 0.75rem; border-radius: 12px; font-size: 0.85rem; font-weight: 600;" data-testid="badge-status-admin">Admin</span>'
                                                : user.blocked 
                                                    ? '<span style="background: #fee2e2; color: #ef4444; padding: 0.375rem 0.75rem; border-radius: 12px; font-size: 0.85rem; font-weight: 600;" data-testid="badge-status-blocked">Blocked</span>'
                                                    : '<span style="background: #d1fae5; color: #10b981; padding: 0.375rem 0.75rem; border-radius: 12px; font-size: 0.85rem; font-weight: 600;" data-testid="badge-status-active">Active</span>'
                                            }
                                        </td>
                                        <td style="padding: 1rem;">
                                            <div style="display: flex; gap: 0.5rem; flex-wrap: wrap;">
                                                ${!user.isAdmin ? `
                                                    <button onclick="openAddFundsModal('${user.email}', '${user.name}')" style="background: #10b981; color: white; border: none; padding: 0.5rem 1rem; border-radius: 6px; font-weight: 600; cursor: pointer; font-size: 0.85rem;" data-testid="button-add-funds-${index}">
                                                        Add Funds
                                                    </button>
                                                    ${user.blocked 
                                                        ? `<button onclick="toggleBlockUser('${user.email}', false)" style="background: #3b82f6; color: white; border: none; padding: 0.5rem 1rem; border-radius: 6px; font-weight: 600; cursor: pointer; font-size: 0.85rem;" data-testid="button-unblock-${index}">Unblock</button>`
                                                        : `<button onclick="toggleBlockUser('${user.email}', true)" style="background: #f59e0b; color: white; border: none; padding: 0.5rem 1rem; border-radius: 6px; font-weight: 600; cursor: pointer; font-size: 0.85rem;" data-testid="button-block-${index}">Block</button>`
                                                    }
                                                    <button onclick="deleteUser('${user.email}', '${user.name}')" style="background: #ef4444; color: white; border: none; padding: 0.5rem 1rem; border-radius: 6px; font-weight: 600; cursor: pointer; font-size: 0.85rem;" data-testid="button-delete-${index}">
                                                        Delete
                                                    </button>
                                                ` : '<span style="color: var(--text-secondary);">Admin account</span>'}
                                            </div>
                                        </td>
                                    </tr>
                                `).join('')}
                            </tbody>
                        </table>
                    </div>
                </div>

                <!-- Add Funds Modal -->
                <div id="addFundsModal" style="display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0, 0, 0, 0.5); z-index: 2000; align-items: center; justify-content: center;" data-testid="modal-add-funds">
                    <div style="background: white; padding: 2rem; border-radius: 16px; max-width: 400px; width: 90%;">
                        <h3 style="font-size: 1.5rem; font-weight: 700; color: var(--dark-gray); margin-bottom: 1rem;" data-testid="text-modal-title">Add Funds</h3>
                        <div style="margin-bottom: 1.5rem;">
                            <div style="margin-bottom: 1rem;">
                                <label style="display: block; font-weight: 600; color: var(--dark-gray); margin-bottom: 0.5rem;">User</label>
                                <div id="addFundsUserName" data-testid="text-add-funds-user"></div>
                            </div>
                            <div>
                                <label style="display: block; font-weight: 600; color: var(--dark-gray); margin-bottom: 0.5rem;">Amount ($)</label>
                                <input type="number" id="fundsAmount" min="0.01" step="0.01" placeholder="Enter amount" style="width: 100%; padding: 0.75rem; border: 2px solid var(--border-color); border-radius: 8px; font-size: 1rem;" data-testid="input-funds-amount">
                            </div>
                        </div>
                        <div style="display: flex; gap: 0.75rem; justify-content: flex-end;">
                            <button onclick="closeAddFundsModal()" style="background: var(--light-gray); color: var(--dark-gray); padding: 0.75rem 1.5rem; border: none; border-radius: 8px; font-weight: 600; cursor: pointer;" data-testid="button-cancel-funds">Cancel</button>
                            <button onclick="confirmAddFunds()" style="background: var(--primary-blue); color: white; padding: 0.75rem 1.5rem; border: none; border-radius: 8px; font-weight: 600; cursor: pointer;" data-testid="button-confirm-funds">Add Funds</button>
                        </div>
                    </div>
                </div>
            `;
        } catch (error) {
            console.error('Error loading users:', error);
            pageContainer.innerHTML = '<div style="text-align: center; padding: 3rem; color: #ef4444;">Failed to load users</div>';
        }
    }

    let selectedUserEmail = '';

    window.openAddFundsModal = function(email, name) {
        selectedUserEmail = email;
        document.getElementById('addFundsUserName').textContent = `${name} (${email})`;
        document.getElementById('fundsAmount').value = '';
        const modal = document.getElementById('addFundsModal');
        modal.style.display = 'flex';
    };

    window.closeAddFundsModal = function() {
        document.getElementById('addFundsModal').style.display = 'none';
        selectedUserEmail = '';
    };

    window.confirmAddFunds = async function() {
        const amount = parseFloat(document.getElementById('fundsAmount').value);
        
        if (!amount || amount <= 0) {
            alert('Please enter a valid amount');
            return;
        }

        try {
            const token = localStorage.getItem('authToken');
            const response = await fetch('/api/admin/add-funds', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`
                },
                body: JSON.stringify({ email: selectedUserEmail, amount: amount })
            });

            const data = await response.json();

            if (response.ok) {
                alert(`Successfully added $${amount.toFixed(2)} to the account`);
                closeAddFundsModal();
                await loadUsersPage();
            } else {
                alert(data.error || 'Failed to add funds');
            }
        } catch (error) {
            console.error('Add funds error:', error);
            alert('An error occurred while adding funds');
        }
    };

    window.toggleBlockUser = async function(email, block) {
        const action = block ? 'block' : 'unblock';
        if (!confirm(`Are you sure you want to ${action} this user?`)) return;

        try {
            const token = localStorage.getItem('authToken');
            const response = await fetch('/api/admin/block-user', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`
                },
                body: JSON.stringify({ email: email, blocked: block })
            });

            const data = await response.json();

            if (response.ok) {
                alert(data.message);
                await loadUsersPage();
            } else {
                alert(data.error || `Failed to ${action} user`);
            }
        } catch (error) {
            console.error('Block user error:', error);
            alert('An error occurred');
        }
    };

    window.deleteUser = async function(email, name) {
        if (!confirm(`Are you sure you want to DELETE ${name}? This action cannot be undone.`)) return;
        if (!confirm('This will permanently delete the user and all their data. Are you absolutely sure?')) return;

        try {
            const token = localStorage.getItem('authToken');
            const response = await fetch('/api/admin/delete-user', {
                method: 'DELETE',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`
                },
                body: JSON.stringify({ email: email })
            });

            const data = await response.json();

            if (response.ok) {
                alert(data.message);
                await loadUsersPage();
            } else {
                alert(data.error || 'Failed to delete user');
            }
        } catch (error) {
            console.error('Delete user error:', error);
            alert('An error occurred while deleting user');
        }
    };

    // ========== SECURITY LOGS PAGE ==========
    async function loadSecurityPage() {
        try {
            const token = localStorage.getItem('authToken');
            const response = await fetch('/api/admin/security-logs?type=all&limit=100', {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            const data = await response.json();

            pageContainer.innerHTML = `
                <div class="page-header">
                    <h1 class="page-title" data-testid="text-page-title">Security Logs</h1>
                    <p class="page-subtitle" data-testid="text-page-subtitle">Monitor login attempts and security events</p>
                </div>

                <div style="display: grid; gap: 1.5rem;">
                    <!-- Login Logs -->
                    <div style="background: white; padding: 2rem; border-radius: 16px; box-shadow: 0 4px 20px rgba(0, 0, 0, 0.08);">
                        <h2 style="font-size: 1.5rem; font-weight: 700; margin-bottom: 1rem; color: var(--dark-gray);" data-testid="text-login-logs-title">Login Attempts</h2>
                        <div style="overflow-x: auto; max-height: 400px; overflow-y: auto;">
                            <table style="width: 100%; border-collapse: collapse;" data-testid="table-login-logs">
                                <thead style="background: var(--light-gray); position: sticky; top: 0;">
                                    <tr>
                                        <th style="text-align: left; padding: 0.75rem; font-weight: 600; font-size: 0.9rem;">Time</th>
                                        <th style="text-align: left; padding: 0.75rem; font-weight: 600; font-size: 0.9rem;">Email</th>
                                        <th style="text-align: left; padding: 0.75rem; font-weight: 600; font-size: 0.9rem;">IP Address</th>
                                        <th style="text-align: left; padding: 0.75rem; font-weight: 600; font-size: 0.9rem;">Status</th>
                                        <th style="text-align: left; padding: 0.75rem; font-weight: 600; font-size: 0.9rem;">Reason</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    ${data.login_logs.map((log, index) => `
                                        <tr style="border-bottom: 1px solid var(--border-color);" data-testid="row-login-${index}">
                                            <td style="padding: 0.75rem; font-size: 0.85rem;">${formatTimestamp(log.timestamp)}</td>
                                            <td style="padding: 0.75rem; font-size: 0.85rem;">${log.email}</td>
                                            <td style="padding: 0.75rem; font-size: 0.85rem;">${log.ip_address}</td>
                                            <td style="padding: 0.75rem;">
                                                ${log.success 
                                                    ? '<span style="background: #d1fae5; color: #10b981; padding: 0.25rem 0.625rem; border-radius: 8px; font-size: 0.8rem; font-weight: 600;">Success</span>'
                                                    : '<span style="background: #fee2e2; color: #ef4444; padding: 0.25rem 0.625rem; border-radius: 8px; font-size: 0.8rem; font-weight: 600;">Failed</span>'
                                                }
                                            </td>
                                            <td style="padding: 0.75rem; font-size: 0.85rem; color: var(--text-secondary);">${log.reason || 'N/A'}</td>
                                        </tr>
                                    `).join('')}
                                </tbody>
                            </table>
                        </div>
                    </div>

                    <!-- Security Events -->
                    <div style="background: white; padding: 2rem; border-radius: 16px; box-shadow: 0 4px 20px rgba(0, 0, 0, 0.08);">
                        <h2 style="font-size: 1.5rem; font-weight: 700; margin-bottom: 1rem; color: var(--dark-gray);" data-testid="text-security-events-title">Security Events</h2>
                        <div style="overflow-x: auto; max-height: 400px; overflow-y: auto;">
                            <table style="width: 100%; border-collapse: collapse;" data-testid="table-security-events">
                                <thead style="background: var(--light-gray); position: sticky; top: 0;">
                                    <tr>
                                        <th style="text-align: left; padding: 0.75rem; font-weight: 600; font-size: 0.9rem;">Time</th>
                                        <th style="text-align: left; padding: 0.75rem; font-weight: 600; font-size: 0.9rem;">Type</th>
                                        <th style="text-align: left; padding: 0.75rem; font-weight: 600; font-size: 0.9rem;">Severity</th>
                                        <th style="text-align: left; padding: 0.75rem; font-weight: 600; font-size: 0.9rem;">Description</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    ${data.security_events.map((event, index) => `
                                        <tr style="border-bottom: 1px solid var(--border-color);" data-testid="row-event-${index}">
                                            <td style="padding: 0.75rem; font-size: 0.85rem;">${formatTimestamp(event.timestamp)}</td>
                                            <td style="padding: 0.75rem; font-size: 0.85rem; font-weight: 600;">${formatEventType(event.type)}</td>
                                            <td style="padding: 0.75rem;">
                                                ${getSeverityBadge(event.severity)}
                                            </td>
                                            <td style="padding: 0.75rem; font-size: 0.85rem;">${event.description}</td>
                                        </tr>
                                    `).join('')}
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            `;
        } catch (error) {
            console.error('Error loading security logs:', error);
            pageContainer.innerHTML = '<div style="text-align: center; padding: 3rem; color: #ef4444;">Failed to load security logs</div>';
        }
    }

    function formatTimestamp(timestamp) {
        const date = new Date(timestamp);
        return date.toLocaleString();
    }

    function formatEventType(type) {
        return type.split('_').map(word => word.charAt(0).toUpperCase() + word.slice(1)).join(' ');
    }

    function getSeverityBadge(severity) {
        const colors = {
            'low': { bg: '#dbeafe', color: '#3b82f6' },
            'medium': { bg: '#fef3c7', color: '#f59e0b' },
            'high': { bg: '#fed7aa', color: '#ea580c' },
            'critical': { bg: '#fee2e2', color: '#dc2626' }
        };
        const style = colors[severity] || colors.low;
        return `<span style="background: ${style.bg}; color: ${style.color}; padding: 0.25rem 0.625rem; border-radius: 8px; font-size: 0.8rem; font-weight: 600;">${severity.toUpperCase()}</span>`;
    }

    // ========== CYBERGUARD AI PAGE ==========
    async function loadCyberGuardPage() {
        try {
            const token = localStorage.getItem('authToken');
            const [statusRes, threatsRes] = await Promise.all([
                fetch('/api/admin/cyberguard/status', {
                    headers: { 'Authorization': `Bearer ${token}` }
                }),
                fetch('/api/admin/cyberguard/threats?limit=50', {
                    headers: { 'Authorization': `Bearer ${token}` }
                })
            ]);

            const statusData = await statusRes.json();
            const threatsData = await threatsRes.json();

            pageContainer.innerHTML = `
                <div class="page-header">
                    <h1 class="page-title" data-testid="text-page-title">🛡️ CyberGuardAI</h1>
                    <p class="page-subtitle" data-testid="text-page-subtitle">AI-Powered Threat Detection & Analysis Engine</p>
                </div>

                <!-- Status Cards -->
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 2rem;">
                    <div style="background: ${statusData.gemini_enabled ? '#d1fae5' : '#fed7aa'}; padding: 1.5rem; border-radius: 12px;">
                        <div style="font-size: 0.9rem; color: var(--dark-gray); margin-bottom: 0.5rem; font-weight: 600;">Gemini AI</div>
                        <div style="font-size: 1.5rem; font-weight: 700; color: ${statusData.gemini_enabled ? '#10b981' : '#ea580c'};" data-testid="status-gemini">
                            ${statusData.gemini_enabled ? '✓ Active' : '⚠ Inactive'}
                        </div>
                    </div>
                    <div style="background: #d1fae5; padding: 1.5rem; border-radius: 12px;">
                        <div style="font-size: 0.9rem; color: var(--dark-gray); margin-bottom: 0.5rem; font-weight: 600;">Local Detection</div>
                        <div style="font-size: 1.5rem; font-weight: 700; color: #10b981;" data-testid="status-local">✓ Active</div>
                    </div>
                    <div style="background: #dbeafe; padding: 1.5rem; border-radius: 12px;">
                        <div style="font-size: 0.9rem; color: var(--dark-gray); margin-bottom: 0.5rem; font-weight: 600;">Threats Detected</div>
                        <div style="font-size: 1.5rem; font-weight: 700; color: #3b82f6;" data-testid="count-threats">${statusData.total_threats_detected}</div>
                    </div>
                    <div style="background: #d1fae5; padding: 1.5rem; border-radius: 12px;">
                        <div style="font-size: 0.9rem; color: var(--dark-gray); margin-bottom: 0.5rem; font-weight: 600;">Protection Status</div>
                        <div style="font-size: 1.5rem; font-weight: 700; color: #10b981;" data-testid="status-protection">🛡️ Active</div>
                    </div>
                </div>

                ${!statusData.gemini_enabled ? `
                <div style="background: #fef3c7; border-left: 4px solid #f59e0b; padding: 1.5rem; border-radius: 8px; margin-bottom: 2rem;">
                    <div style="font-weight: 700; color: #92400e; margin-bottom: 0.5rem;">⚠️ Gemini AI Not Configured</div>
                    <div style="color: #78350f; font-size: 0.95rem;">
                        To enable advanced AI-powered threat detection, set your GEMINI_API_KEY environment variable. 
                        Get your API key from <a href="https://makersuite.google.com/app/apikey" target="_blank" style="color: #0052CC; font-weight: 600;">Google AI Studio</a>.
                    </div>
                </div>
                ` : ''}

                <!-- Threat Analyzer -->
                <div style="background: white; padding: 2rem; border-radius: 16px; box-shadow: 0 4px 20px rgba(0, 0, 0, 0.08); margin-bottom: 2rem;">
                    <h2 style="font-size: 1.5rem; font-weight: 700; margin-bottom: 1rem; color: var(--dark-gray);" data-testid="text-analyzer-title">Real-Time Threat Analyzer</h2>
                    <p style="color: var(--text-secondary); margin-bottom: 1.5rem;">Analyze text for SQL injection, XSS, command injection, and other security threats.</p>
                    
                    <div style="margin-bottom: 1rem;">
                        <label style="display: block; font-weight: 600; color: var(--dark-gray); margin-bottom: 0.5rem;">Text to Analyze</label>
                        <textarea id="analyzeText" placeholder="Enter any text, code, or input to analyze for security threats..." style="width: 100%; min-height: 150px; padding: 1rem; border: 2px solid var(--border-color); border-radius: 8px; font-size: 1rem; font-family: monospace; resize: vertical;" data-testid="input-analyze-text"></textarea>
                    </div>
                    
                    <button onclick="analyzeText()" style="background: var(--primary-blue); color: white; border: none; padding: 0.875rem 2rem; border-radius: 8px; font-weight: 600; cursor: pointer; font-size: 1rem;" data-testid="button-analyze">
                        🔍 Analyze for Threats
                    </button>

                    <div id="analysisResult" style="margin-top: 1.5rem; display: none;" data-testid="container-analysis-result"></div>
                </div>

                <!-- Threat History -->
                <div style="background: white; padding: 2rem; border-radius: 16px; box-shadow: 0 4px 20px rgba(0, 0, 0, 0.08);">
                    <h2 style="font-size: 1.5rem; font-weight: 700; margin-bottom: 1rem; color: var(--dark-gray);" data-testid="text-history-title">Threat Detection History</h2>
                    
                    ${threatsData.threats.length === 0 ? `
                        <div style="text-align: center; padding: 3rem; color: var(--text-secondary);">
                            <div style="font-size: 3rem; margin-bottom: 1rem;">🎉</div>
                            <div style="font-size: 1.1rem; font-weight: 600;">No threats detected yet!</div>
                            <div style="font-size: 0.95rem; margin-top: 0.5rem;">Your system is secure.</div>
                        </div>
                    ` : `
                        <div style="overflow-x: auto; max-height: 500px; overflow-y: auto;">
                            ${threatsData.threats.map((threat, index) => `
                                <div style="border: 2px solid ${getThreatColor(threat.analysis.severity)}; border-radius: 12px; padding: 1.5rem; margin-bottom: 1rem; background: ${getThreatBgColor(threat.analysis.severity)};" data-testid="card-threat-${index}">
                                    <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 1rem;">
                                        <div>
                                            <div style="font-weight: 700; font-size: 1.1rem; color: var(--dark-gray); margin-bottom: 0.25rem;">${threat.analysis.threat_type}</div>
                                            <div style="font-size: 0.85rem; color: var(--text-secondary);">${formatTimestamp(threat.timestamp)}</div>
                                        </div>
                                        ${getSeverityBadge(threat.analysis.severity)}
                                    </div>
                                    
                                    <div style="background: white; padding: 1rem; border-radius: 8px; margin-bottom: 1rem; border: 1px solid var(--border-color);">
                                        <div style="font-weight: 600; font-size: 0.85rem; color: var(--dark-gray); margin-bottom: 0.5rem;">Analyzed Text:</div>
                                        <div style="font-family: monospace; font-size: 0.9rem; color: var(--text-secondary); word-break: break-all;">${threat.text}</div>
                                    </div>

                                    ${threat.analysis.patterns && threat.analysis.patterns.length > 0 ? `
                                        <div style="margin-bottom: 1rem;">
                                            <div style="font-weight: 600; font-size: 0.85rem; color: var(--dark-gray); margin-bottom: 0.5rem;">Patterns Detected:</div>
                                            <div style="display: flex; flex-wrap: wrap; gap: 0.5rem;">
                                                ${threat.analysis.patterns.map(pattern => `
                                                    <span style="background: #fee2e2; color: #dc2626; padding: 0.375rem 0.75rem; border-radius: 8px; font-size: 0.8rem; font-family: monospace;">${pattern}</span>
                                                `).join('')}
                                            </div>
                                        </div>
                                    ` : ''}

                                    <div style="margin-bottom: 1rem;">
                                        <div style="font-weight: 600; font-size: 0.85rem; color: var(--dark-gray); margin-bottom: 0.5rem;">Recommendation:</div>
                                        <div style="font-size: 0.9rem; color: var(--dark-gray);">${threat.analysis.recommendation}</div>
                                    </div>

                                    <div>
                                        <div style="font-weight: 600; font-size: 0.85rem; color: var(--dark-gray); margin-bottom: 0.5rem;">Explanation:</div>
                                        <div style="font-size: 0.9rem; color: var(--text-secondary);">${threat.analysis.explanation}</div>
                                    </div>

                                    <div style="margin-top: 1rem; padding-top: 1rem; border-top: 1px solid var(--border-color);">
                                        <span style="font-size: 0.8rem; color: var(--text-secondary);">Detection Source: ${threat.source === 'gemini_ai' ? '🤖 Gemini AI' : '🔧 Local Detection'}</span>
                                    </div>
                                </div>
                            `).join('')}
                        </div>
                    `}
                </div>
            `;
        } catch (error) {
            console.error('Error loading CyberGuard page:', error);
            pageContainer.innerHTML = '<div style="text-align: center; padding: 3rem; color: #ef4444;">Failed to load CyberGuardAI</div>';
        }
    }

    function getThreatColor(severity) {
        const colors = {
            'low': '#93c5fd',
            'medium': '#fde047',
            'high': '#fdba74',
            'critical': '#fca5a5'
        };
        return colors[severity] || colors.low;
    }

    function getThreatBgColor(severity) {
        const colors = {
            'low': '#eff6ff',
            'medium': '#fefce8',
            'high': '#fff7ed',
            'critical': '#fef2f2'
        };
        return colors[severity] || colors.low;
    }

    window.analyzeText = async function() {
        const text = document.getElementById('analyzeText').value.trim();
        const resultDiv = document.getElementById('analysisResult');

        if (!text) {
            alert('Please enter text to analyze');
            return;
        }

        resultDiv.innerHTML = '<div style="text-align: center; padding: 2rem; color: var(--text-secondary);">⏳ Analyzing...</div>';
        resultDiv.style.display = 'block';

        try {
            const token = localStorage.getItem('authToken');
            const response = await fetch('/api/admin/cyberguard/analyze', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`
                },
                body: JSON.stringify({ text: text })
            });

            const data = await response.json();

            if (response.ok) {
                const analysis = data.analysis;
                resultDiv.innerHTML = `
                    <div style="border: 2px solid ${getThreatColor(analysis.severity)}; border-radius: 12px; padding: 1.5rem; background: ${getThreatBgColor(analysis.severity)};">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem;">
                            <div style="font-weight: 700; font-size: 1.2rem; color: var(--dark-gray);">
                                ${analysis.threat_detected ? '⚠️ Threat Detected' : '✅ No Threats Found'}
                            </div>
                            ${getSeverityBadge(analysis.severity)}
                        </div>

                        ${analysis.threat_detected ? `
                            <div style="margin-bottom: 1rem;">
                                <div style="font-weight: 600; margin-bottom: 0.5rem;">Threat Type:</div>
                                <div style="font-size: 1.1rem; color: #dc2626;">${analysis.threat_type}</div>
                            </div>

                            ${analysis.patterns && analysis.patterns.length > 0 ? `
                                <div style="margin-bottom: 1rem;">
                                    <div style="font-weight: 600; margin-bottom: 0.5rem;">Patterns:</div>
                                    <div style="display: flex; flex-wrap: wrap; gap: 0.5rem;">
                                        ${analysis.patterns.map(pattern => `
                                            <span style="background: #fee2e2; color: #dc2626; padding: 0.375rem 0.75rem; border-radius: 8px; font-size: 0.85rem; font-family: monospace;">${pattern}</span>
                                        `).join('')}
                                    </div>
                                </div>
                            ` : ''}
                        ` : ''}

                        <div style="margin-bottom: 1rem;">
                            <div style="font-weight: 600; margin-bottom: 0.5rem;">Recommendation:</div>
                            <div>${analysis.recommendation}</div>
                        </div>

                        <div>
                            <div style="font-weight: 600; margin-bottom: 0.5rem;">Explanation:</div>
                            <div style="color: var(--text-secondary);">${analysis.explanation}</div>
                        </div>

                        <div style="margin-top: 1rem; padding-top: 1rem; border-top: 1px solid var(--border-color);">
                            <span style="font-size: 0.85rem; color: var(--text-secondary);">
                                Detection Source: ${data.source === 'gemini_ai' ? '🤖 Gemini AI (Advanced)' : '🔧 Local Detection (Basic)'}
                            </span>
                        </div>
                    </div>
                `;
            } else {
                resultDiv.innerHTML = '<div style="padding: 1.5rem; background: #fee2e2; border-radius: 8px; color: #dc2626;">Error: ' + (data.error || 'Analysis failed') + '</div>';
            }
        } catch (error) {
            console.error('Analysis error:', error);
            resultDiv.innerHTML = '<div style="padding: 1.5rem; background: #fee2e2; border-radius: 8px; color: #dc2626;">Network error occurred</div>';
        }
    };
});
