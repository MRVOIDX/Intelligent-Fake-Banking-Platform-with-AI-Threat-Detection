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
    let alertPollingInterval = null;

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

    const user = await checkAuth();
    if (!user) return;

    userName.textContent = user.name;
    userAvatar.textContent = user.name.charAt(0).toUpperCase();
    loadingState.style.display = 'none';

    navItems.forEach(item => {
        item.addEventListener('click', function() {
            navItems.forEach(nav => nav.classList.remove('active'));
            this.classList.add('active');
            
            const page = this.getAttribute('data-page');
            loadPage(page);
        });
    });

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

    await updateAlertBadge();
    startAlertPolling();

    loadPage('dashboard');

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
            case 'alerts':
                await loadAlertsPage();
                break;
            case 'database':
                await loadDatabasePage();
                break;
        }
    }

    async function updateAlertBadge() {
        try {
            const token = localStorage.getItem('authToken');
            const response = await fetch('/api/admin/alerts/count', {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            const data = await response.json();
            
            const alertNav = document.querySelector('[data-page="alerts"]');
            if (alertNav) {
                let badge = alertNav.querySelector('.alert-badge');
                if (data.unread_count > 0) {
                    if (!badge) {
                        badge = document.createElement('span');
                        badge.className = 'alert-badge';
                        alertNav.appendChild(badge);
                    }
                    badge.textContent = data.unread_count > 99 ? '99+' : data.unread_count;
                    badge.style.cssText = 'background: #ef4444; color: white; padding: 0.125rem 0.5rem; border-radius: 12px; font-size: 0.75rem; font-weight: 700; margin-left: auto;';
                } else if (badge) {
                    badge.remove();
                }
            }
        } catch (error) {
            console.error('Error updating alert badge:', error);
        }
    }

    function startAlertPolling() {
        if (alertPollingInterval) clearInterval(alertPollingInterval);
        alertPollingInterval = setInterval(updateAlertBadge, 30000);
    }

    async function loadDashboardPage() {
        try {
            const token = localStorage.getItem('authToken');
            const [usersRes, statsRes, alertsRes] = await Promise.all([
                fetch('/api/admin/users', {
                    headers: { 'Authorization': `Bearer ${token}` }
                }),
                fetch('/api/admin/security-stats', {
                    headers: { 'Authorization': `Bearer ${token}` }
                }),
                fetch('/api/admin/alerts?limit=5&unread_only=true', {
                    headers: { 'Authorization': `Bearer ${token}` }
                })
            ]);

            const usersData = await usersRes.json();
            const statsData = await statsRes.json();
            const alertsData = await alertsRes.json();

            const totalUsers = usersData.users.length;
            const activeUsers = usersData.users.filter(u => !u.blocked && !u.isAdmin).length;
            
            pageContainer.innerHTML = `
                <div class="page-header">
                    <h1 class="page-title" data-testid="text-page-title">Dashboard Overview</h1>
                    <p class="page-subtitle" data-testid="text-page-subtitle">Real-time statistics and system health</p>
                </div>

                ${alertsData.alerts && alertsData.alerts.length > 0 ? `
                <div style="background: linear-gradient(135deg, #fef2f2 0%, #fee2e2 100%); border: 2px solid #fca5a5; padding: 1.5rem; border-radius: 16px; margin-bottom: 2rem;" data-testid="container-alerts-preview">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem;">
                        <h2 style="font-size: 1.25rem; font-weight: 700; color: #dc2626; display: flex; align-items: center; gap: 0.5rem;">
                            <span style="font-size: 1.5rem;">AI</span> AI Security Alerts
                            <span style="background: #dc2626; color: white; padding: 0.25rem 0.75rem; border-radius: 12px; font-size: 0.8rem;">${alertsData.unread_count} New</span>
                        </h2>
                        <button onclick="navigateTo('alerts')" style="background: #dc2626; color: white; border: none; padding: 0.5rem 1rem; border-radius: 8px; font-weight: 600; cursor: pointer;" data-testid="button-view-all-alerts">
                            View All Alerts
                        </button>
                    </div>
                    <div style="display: grid; gap: 0.75rem;">
                        ${alertsData.alerts.slice(0, 3).map((alert, index) => `
                            <div style="background: white; padding: 1rem; border-radius: 8px; border-left: 4px solid ${getAlertColor(alert.severity)};" data-testid="alert-preview-${index}">
                                <div style="display: flex; justify-content: space-between; align-items: flex-start;">
                                    <div>
                                        <div style="font-weight: 600; color: var(--dark-gray); margin-bottom: 0.25rem;">${alert.title}</div>
                                        <div style="font-size: 0.9rem; color: var(--text-secondary);">${alert.message.substring(0, 100)}${alert.message.length > 100 ? '...' : ''}</div>
                                    </div>
                                    ${getSeverityBadge(alert.severity)}
                                </div>
                            </div>
                        `).join('')}
                    </div>
                </div>
                ` : ''}

                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 1.5rem; margin-bottom: 2rem;">
                    ${createStatCard('Total Users', totalUsers, 'users', 'var(--primary-blue)', 'stat-total-users')}
                    ${createStatCard('Active Users', activeUsers, 'check', '#10b981', 'stat-active-users')}
                    ${createStatCard('Blocked Users', statsData.blocked_users_count, 'block', '#f59e0b', 'stat-blocked-users')}
                    ${createStatCard('Failed Logins', statsData.failed_logins, 'warning', '#ef4444', 'stat-failed-logins')}
                    ${createStatCard('Brute Force Attempts', statsData.brute_force_attempts, 'fire', '#dc2626', 'stat-brute-force')}
                    ${createStatCard('Threat Detections', statsData.total_threats_detected || 0, 'shield', '#8b5cf6', 'stat-threats')}
                </div>

                <div style="background: white; padding: 2rem; border-radius: 16px; box-shadow: 0 4px 20px rgba(0, 0, 0, 0.08);">
                    <h2 style="font-size: 1.5rem; font-weight: 700; margin-bottom: 1rem; color: var(--dark-gray);" data-testid="text-quick-actions">Quick Actions</h2>
                    <div style="display: flex; gap: 1rem; flex-wrap: wrap;">
                        <button onclick="navigateTo('users')" class="action-btn" data-testid="button-manage-users">
                            Manage Users
                        </button>
                        <button onclick="navigateTo('security')" class="action-btn" data-testid="button-view-logs">
                            View Security Logs
                        </button>
                        <button onclick="navigateTo('cyberguard')" class="action-btn" data-testid="button-cyberguard">
                            CyberGuardAI
                        </button>
                        <button onclick="navigateTo('alerts')" class="action-btn" style="background: #dc2626;" data-testid="button-alerts">
                            AI Alerts ${alertsData.unread_count > 0 ? `(${alertsData.unread_count})` : ''}
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
                        filter: brightness(0.9);
                        transform: translateY(-2px);
                    }
                </style>
            `;
        } catch (error) {
            console.error('Error loading dashboard:', error);
            pageContainer.innerHTML = '<div style="text-align: center; padding: 3rem; color: #ef4444;">Failed to load dashboard</div>';
        }
    }

    function getAlertColor(severity) {
        const colors = {
            'critical': '#dc2626',
            'high': '#ea580c',
            'medium': '#f59e0b',
            'low': '#3b82f6'
        };
        return colors[severity] || colors.low;
    }

    function createStatCard(title, value, icon, color, testId) {
        const iconMap = {
            'users': '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"></path><circle cx="9" cy="7" r="4"></circle><path d="M23 21v-2a4 4 0 0 0-3-3.87"></path><path d="M16 3.13a4 4 0 0 1 0 7.75"></path></svg>',
            'check': '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>',
            'block': '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"></line></svg>',
            'warning': '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>',
            'fire': '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M8.5 14.5A2.5 2.5 0 0 0 11 12c0-1.38-.5-2-1-3-1.072-2.143-.224-4.054 2-6 .5 2.5 2 4.9 4 6.5 2 1.6 3 3.5 3 5.5a7 7 0 1 1-14 0c0-1.153.433-2.294 1-3a2.5 2.5 0 0 0 2.5 2.5z"></path></svg>',
            'shield': '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>'
        };
        
        return `
            <div style="background: white; padding: 1.5rem; border-radius: 12px; box-shadow: 0 2px 10px rgba(0, 0, 0, 0.08);" data-testid="card-${testId}">
                <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 0.75rem;">
                    <div style="font-size: 0.9rem; color: var(--text-secondary); font-weight: 500;">${title}</div>
                    <div style="color: ${color};">${iconMap[icon] || ''}</div>
                </div>
                <div style="font-size: 2rem; font-weight: 700; color: ${color};" data-testid="value-${testId}">${value}</div>
            </div>
        `;
    }

    window.navigateTo = function(page) {
        const navItem = document.querySelector(`[data-page="${page}"]`);
        if (navItem) {
            navItem.click();
        } else {
            loadPage(page);
        }
    };

    async function loadAlertsPage() {
        try {
            const token = localStorage.getItem('authToken');
            const response = await fetch('/api/admin/alerts?limit=100', {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            const data = await response.json();

            pageContainer.innerHTML = `
                <div class="page-header">
                    <h1 class="page-title" data-testid="text-page-title">AI Security Alerts</h1>
                    <p class="page-subtitle" data-testid="text-page-subtitle">Real-time threat notifications powered by Groq API</p>
                </div>

                <div style="display: flex; gap: 1rem; margin-bottom: 2rem; flex-wrap: wrap;">
                    <div style="background: ${data.unread_count > 0 ? '#fef2f2' : '#f0fdf4'}; padding: 1rem 1.5rem; border-radius: 12px; display: flex; align-items: center; gap: 0.75rem;">
                        <span style="font-size: 1.5rem;">${data.unread_count > 0 ? '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#dc2626" stroke-width="2"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"></path><path d="M13.73 21a2 2 0 0 1-3.46 0"></path></svg>' : '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#16a34a" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>'}</span>
                        <div>
                            <div style="font-weight: 600; color: var(--dark-gray);">${data.unread_count} Unread Alerts</div>
                            <div style="font-size: 0.85rem; color: var(--text-secondary);">Total: ${data.alerts.length} alerts</div>
                        </div>
                    </div>
                </div>

                <div style="background: white; padding: 2rem; border-radius: 16px; box-shadow: 0 4px 20px rgba(0, 0, 0, 0.08);">
                    ${data.alerts.length === 0 ? `
                        <div style="text-align: center; padding: 3rem; color: var(--text-secondary);">
                            <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" style="margin: 0 auto 1rem;"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path><path d="M9 12l2 2 4-4"></path></svg>
                            <div style="font-size: 1.25rem; font-weight: 600; margin-bottom: 0.5rem;">All Clear!</div>
                            <div>No security alerts at this time. Your system is protected.</div>
                        </div>
                    ` : `
                        <div style="display: grid; gap: 1rem;" data-testid="container-alerts-list">
                            ${data.alerts.map((alert, index) => `
                                <div style="border: 2px solid ${getAlertColor(alert.severity)}20; border-left: 4px solid ${getAlertColor(alert.severity)}; border-radius: 12px; padding: 1.5rem; background: ${alert.is_read ? 'white' : getAlertColor(alert.severity) + '08'};" data-testid="card-alert-${index}">
                                    <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 1rem;">
                                        <div style="flex: 1;">
                                            <div style="display: flex; align-items: center; gap: 0.75rem; margin-bottom: 0.5rem;">
                                                ${!alert.is_read ? '<span style="width: 8px; height: 8px; background: #dc2626; border-radius: 50%;"></span>' : ''}
                                                <span style="font-weight: 700; font-size: 1.1rem; color: var(--dark-gray);">${alert.title}</span>
                                                ${getSeverityBadge(alert.severity)}
                                            </div>
                                            <div style="font-size: 0.85rem; color: var(--text-secondary);">${formatTimestamp(alert.created_at)}</div>
                                        </div>
                                        <div style="display: flex; gap: 0.5rem; flex-wrap: wrap;">
                                            <button onclick="analyzeAlertWithAI(${alert.id})" style="background: #8b5cf6; color: white; border: none; padding: 0.5rem 0.75rem; border-radius: 6px; cursor: pointer; display: flex; align-items: center; gap: 0.25rem; font-size: 0.85rem;" data-testid="button-analyze-ai-${index}">
                                                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"></path><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>
                                                Analyze with AI
                                            </button>
                                            ${!alert.is_read ? `
                                                <button onclick="markAlertRead(${alert.id})" style="background: var(--light-gray); border: none; padding: 0.5rem; border-radius: 6px; cursor: pointer; display: flex; align-items: center; gap: 0.25rem; font-size: 0.85rem;" data-testid="button-mark-read-${index}">
                                                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>
                                                    Mark Read
                                                </button>
                                            ` : ''}
                                            <button onclick="dismissAlert(${alert.id})" style="background: #fee2e2; color: #dc2626; border: none; padding: 0.5rem; border-radius: 6px; cursor: pointer; display: flex; align-items: center; gap: 0.25rem; font-size: 0.85rem;" data-testid="button-dismiss-${index}">
                                                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
                                                Dismiss
                                            </button>
                                        </div>
                                    </div>
                                    
                                    <div style="margin-bottom: 1rem;">
                                        <div style="color: var(--dark-gray); line-height: 1.6;">${alert.message}</div>
                                    </div>

                                    ${alert.threat_data ? `
                                        <div style="background: var(--light-gray); padding: 1rem; border-radius: 8px;">
                                            <div style="font-weight: 600; font-size: 0.85rem; color: var(--dark-gray); margin-bottom: 0.5rem;">Threat Details</div>
                                            ${alert.threat_data.text ? `
                                                <div style="margin-bottom: 0.75rem;">
                                                    <div style="font-size: 0.8rem; color: var(--text-secondary); margin-bottom: 0.25rem;">Suspicious Input:</div>
                                                    <div style="font-family: monospace; font-size: 0.85rem; background: white; padding: 0.5rem; border-radius: 4px; word-break: break-all;">${alert.threat_data.text}</div>
                                                </div>
                                            ` : ''}
                                            ${alert.threat_data.patterns && alert.threat_data.patterns.length > 0 ? `
                                                <div style="margin-bottom: 0.75rem;">
                                                    <div style="font-size: 0.8rem; color: var(--text-secondary); margin-bottom: 0.25rem;">Detected Patterns:</div>
                                                    <div style="display: flex; flex-wrap: wrap; gap: 0.5rem;">
                                                        ${alert.threat_data.patterns.map(p => `<span style="background: #fee2e2; color: #dc2626; padding: 0.25rem 0.5rem; border-radius: 4px; font-size: 0.75rem; font-family: monospace;">${p}</span>`).join('')}
                                                    </div>
                                                </div>
                                            ` : ''}
                                            ${alert.threat_data.recommendation ? `
                                                <div>
                                                    <div style="font-size: 0.8rem; color: var(--text-secondary); margin-bottom: 0.25rem;">Recommended Action:</div>
                                                    <div style="font-size: 0.9rem; color: var(--dark-gray);">${alert.threat_data.recommendation}</div>
                                                </div>
                                            ` : ''}
                                        </div>
                                    ` : ''}
                                    
                                    <div style="margin-top: 1rem; padding-top: 1rem; border-top: 1px solid var(--border-color); display: flex; align-items: center; gap: 0.5rem;">
                                        <span style="font-size: 0.8rem; color: var(--text-secondary);">Alert Type: ${alert.alert_type}</span>
                                        ${alert.threat_data?.source ? `<span style="font-size: 0.8rem; color: var(--text-secondary);">| Source: ${alert.threat_data.source}</span>` : ''}
                                    </div>
                                </div>
                            `).join('')}
                        </div>
                    `}
                </div>
            `;
        } catch (error) {
            console.error('Error loading alerts:', error);
            pageContainer.innerHTML = '<div style="text-align: center; padding: 3rem; color: #ef4444;">Failed to load alerts</div>';
        }
    }

    window.markAlertRead = async function(alertId) {
        try {
            const token = localStorage.getItem('authToken');
            await fetch(`/api/admin/alerts/${alertId}/read`, {
                method: 'POST',
                headers: { 'Authorization': `Bearer ${token}` }
            });
            await loadAlertsPage();
            await updateAlertBadge();
        } catch (error) {
            console.error('Error marking alert as read:', error);
        }
    };

    window.dismissAlert = async function(alertId) {
        try {
            const token = localStorage.getItem('authToken');
            await fetch(`/api/admin/alerts/${alertId}/dismiss`, {
                method: 'POST',
                headers: { 'Authorization': `Bearer ${token}` }
            });
            await loadAlertsPage();
            await updateAlertBadge();
        } catch (error) {
            console.error('Error dismissing alert:', error);
        }
    };

    window.analyzeAlertWithAI = async function(alertId) {
        const button = document.querySelector(`[onclick="analyzeAlertWithAI(${alertId})"]`);
        const originalText = button.innerHTML;
        button.innerHTML = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="spin"><circle cx="12" cy="12" r="10"></circle></svg> Analyzing...';
        button.disabled = true;
        button.style.opacity = '0.7';

        try {
            const token = localStorage.getItem('authToken');
            const response = await fetch(`/api/admin/alerts/${alertId}/analyze`, {
                method: 'POST',
                headers: { 'Authorization': `Bearer ${token}` }
            });

            const result = await response.json();

            if (response.ok && result.success) {
                const analysis = result.analysis;
                const modalHtml = `
                    <div id="aiAnalysisModal" style="position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.5); display: flex; align-items: center; justify-content: center; z-index: 10000; padding: 1rem;">
                        <div style="background: white; border-radius: 16px; max-width: 600px; width: 100%; max-height: 80vh; overflow-y: auto; box-shadow: 0 25px 50px -12px rgba(0,0,0,0.25);">
                            <div style="padding: 1.5rem; border-bottom: 1px solid var(--border-color); display: flex; justify-content: space-between; align-items: center;">
                                <div style="display: flex; align-items: center; gap: 0.75rem;">
                                    <div style="background: #8b5cf6; color: white; width: 40px; height: 40px; border-radius: 10px; display: flex; align-items: center; justify-content: center;">
                                        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"></path><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>
                                    </div>
                                    <div>
                                        <div style="font-weight: 700; font-size: 1.25rem; color: var(--dark-gray);">AI Analysis Results</div>
                                        <div style="font-size: 0.85rem; color: var(--text-secondary);">Powered by Groq API</div>
                                    </div>
                                </div>
                                <button onclick="closeAIModal()" style="background: none; border: none; cursor: pointer; padding: 0.5rem;">
                                    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
                                </button>
                            </div>
                            <div style="padding: 1.5rem;">
                                <div style="display: flex; align-items: center; gap: 1rem; margin-bottom: 1.5rem;">
                                    <div style="flex: 1;">
                                        <div style="font-weight: 600; color: var(--dark-gray); margin-bottom: 0.25rem;">Threat Type</div>
                                        <div style="font-size: 1.1rem; color: ${analysis.threat_detected ? '#dc2626' : '#16a34a'};">${analysis.threat_type}</div>
                                    </div>
                                    ${getSeverityBadge(analysis.severity)}
                                </div>

                                ${analysis.patterns && analysis.patterns.length > 0 ? `
                                    <div style="margin-bottom: 1.5rem;">
                                        <div style="font-weight: 600; color: var(--dark-gray); margin-bottom: 0.5rem;">Detected Patterns</div>
                                        <div style="display: flex; flex-wrap: wrap; gap: 0.5rem;">
                                            ${analysis.patterns.map(p => `<span style="background: #fee2e2; color: #dc2626; padding: 0.375rem 0.75rem; border-radius: 8px; font-size: 0.85rem; font-family: monospace;">${p}</span>`).join('')}
                                        </div>
                                    </div>
                                ` : ''}

                                <div style="margin-bottom: 1.5rem;">
                                    <div style="font-weight: 600; color: var(--dark-gray); margin-bottom: 0.5rem;">Recommendation</div>
                                    <div style="background: #f0fdf4; border-left: 3px solid #16a34a; padding: 1rem; border-radius: 0 8px 8px 0; color: var(--dark-gray);">${analysis.recommendation}</div>
                                </div>

                                <div>
                                    <div style="font-weight: 600; color: var(--dark-gray); margin-bottom: 0.5rem;">Detailed Explanation</div>
                                    <div style="background: var(--light-gray); padding: 1rem; border-radius: 8px; color: var(--text-secondary); line-height: 1.6;">${analysis.explanation}</div>
                                </div>
                            </div>
                            <div style="padding: 1rem 1.5rem; border-top: 1px solid var(--border-color); display: flex; justify-content: flex-end;">
                                <button onclick="closeAIModal()" style="background: var(--primary-blue); color: white; border: none; padding: 0.75rem 1.5rem; border-radius: 8px; font-weight: 600; cursor: pointer;">
                                    Close
                                </button>
                            </div>
                        </div>
                    </div>
                `;
                document.body.insertAdjacentHTML('beforeend', modalHtml);
            } else {
                alert('Error: ' + (result.error || 'Analysis failed'));
            }
        } catch (error) {
            console.error('Error analyzing alert:', error);
            alert('Network error occurred during analysis');
        } finally {
            button.innerHTML = originalText;
            button.disabled = false;
            button.style.opacity = '1';
        }
    };

    window.closeAIModal = function() {
        const modal = document.getElementById('aiAnalysisModal');
        if (modal) modal.remove();
    };

    async function loadUsersPage() {
        try {
            const token = localStorage.getItem('authToken');
            const response = await fetch('/api/admin/users', {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            const data = await response.json();
            currentUsers = data.users;

            const activeUsers = currentUsers.filter(u => !u.blocked && !u.isAdmin).length;
            const blockedUsers = currentUsers.filter(u => u.blocked).length;
            const totalBalance = currentUsers.reduce((sum, u) => sum + (u.account?.balance || 0), 0);

            pageContainer.innerHTML = `
                <div class="page-header">
                    <h1 class="page-title" data-testid="text-page-title">User Management</h1>
                    <p class="page-subtitle" data-testid="text-page-subtitle">Manage user accounts, adjust balances, and control access</p>
                </div>

                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 2rem;">
                    <div style="background: white; padding: 1.5rem; border-radius: 16px; box-shadow: 0 4px 20px rgba(0, 0, 0, 0.08);">
                        <div style="display: flex; align-items: center; gap: 1rem;">
                            <div style="background: #dbeafe; padding: 0.75rem; border-radius: 12px;">
                                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#3b82f6" stroke-width="2">
                                    <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"></path>
                                    <circle cx="9" cy="7" r="4"></circle>
                                    <path d="M23 21v-2a4 4 0 0 0-3-3.87"></path>
                                    <path d="M16 3.13a4 4 0 0 1 0 7.75"></path>
                                </svg>
                            </div>
                            <div>
                                <div style="font-size: 2rem; font-weight: 700; color: var(--dark-gray);">${currentUsers.length}</div>
                                <div style="color: var(--text-secondary); font-size: 0.9rem;">Total Users</div>
                            </div>
                        </div>
                    </div>
                    <div style="background: white; padding: 1.5rem; border-radius: 16px; box-shadow: 0 4px 20px rgba(0, 0, 0, 0.08);">
                        <div style="display: flex; align-items: center; gap: 1rem;">
                            <div style="background: #d1fae5; padding: 0.75rem; border-radius: 12px;">
                                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#10b981" stroke-width="2">
                                    <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path>
                                    <polyline points="22 4 12 14.01 9 11.01"></polyline>
                                </svg>
                            </div>
                            <div>
                                <div style="font-size: 2rem; font-weight: 700; color: var(--dark-gray);">${activeUsers}</div>
                                <div style="color: var(--text-secondary); font-size: 0.9rem;">Active Users</div>
                            </div>
                        </div>
                    </div>
                    <div style="background: white; padding: 1.5rem; border-radius: 16px; box-shadow: 0 4px 20px rgba(0, 0, 0, 0.08);">
                        <div style="display: flex; align-items: center; gap: 1rem;">
                            <div style="background: #fee2e2; padding: 0.75rem; border-radius: 12px;">
                                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#ef4444" stroke-width="2">
                                    <circle cx="12" cy="12" r="10"></circle>
                                    <line x1="4.93" y1="4.93" x2="19.07" y2="19.07"></line>
                                </svg>
                            </div>
                            <div>
                                <div style="font-size: 2rem; font-weight: 700; color: var(--dark-gray);">${blockedUsers}</div>
                                <div style="color: var(--text-secondary); font-size: 0.9rem;">Blocked</div>
                            </div>
                        </div>
                    </div>
                    <div style="background: white; padding: 1.5rem; border-radius: 16px; box-shadow: 0 4px 20px rgba(0, 0, 0, 0.08);">
                        <div style="display: flex; align-items: center; gap: 1rem;">
                            <div style="background: #fef3c7; padding: 0.75rem; border-radius: 12px;">
                                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#f59e0b" stroke-width="2">
                                    <line x1="12" y1="1" x2="12" y2="23"></line>
                                    <path d="M17 5H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H6"></path>
                                </svg>
                            </div>
                            <div>
                                <div style="font-size: 1.5rem; font-weight: 700; color: var(--dark-gray);">$${totalBalance.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}</div>
                                <div style="color: var(--text-secondary); font-size: 0.9rem;">Total Balance</div>
                            </div>
                        </div>
                    </div>
                </div>

                <div style="background: white; padding: 2rem; border-radius: 16px; box-shadow: 0 4px 20px rgba(0, 0, 0, 0.08);">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5rem; gap: 1rem; flex-wrap: wrap;">
                        <h2 style="font-size: 1.5rem; font-weight: 700; color: var(--dark-gray);" data-testid="text-users-title">User Accounts</h2>
                    </div>
                    
                    <div style="display: grid; gap: 1rem;">
                        ${currentUsers.map((user, index) => `
                            <div style="background: var(--light-gray); border-radius: 12px; padding: 1.25rem; display: grid; grid-template-columns: 1fr auto; gap: 1rem; align-items: center;" data-testid="card-user-${index}">
                                <div style="display: flex; align-items: center; gap: 1rem;">
                                    <div style="width: 48px; height: 48px; border-radius: 12px; background: ${user.isAdmin ? '#3b82f6' : user.blocked ? '#ef4444' : '#10b981'}; display: flex; align-items: center; justify-content: center; color: white; font-weight: 700; font-size: 1.2rem;">
                                        ${user.name.charAt(0).toUpperCase()}
                                    </div>
                                    <div style="flex: 1;">
                                        <div style="display: flex; align-items: center; gap: 0.5rem; flex-wrap: wrap;">
                                            <span style="font-weight: 700; color: var(--dark-gray); font-size: 1.1rem;" data-testid="text-user-name-${index}">${user.name}</span>
                                            ${user.isAdmin 
                                                ? '<span style="background: #3b82f6; color: white; padding: 0.25rem 0.5rem; border-radius: 6px; font-size: 0.75rem; font-weight: 600;">ADMIN</span>'
                                                : user.blocked 
                                                    ? '<span style="background: #ef4444; color: white; padding: 0.25rem 0.5rem; border-radius: 6px; font-size: 0.75rem; font-weight: 600;">BLOCKED</span>'
                                                    : '<span style="background: #10b981; color: white; padding: 0.25rem 0.5rem; border-radius: 6px; font-size: 0.75rem; font-weight: 600;">ACTIVE</span>'
                                            }
                                        </div>
                                        <div style="color: var(--text-secondary); font-size: 0.9rem;" data-testid="text-user-email-${index}">${user.email}</div>
                                    </div>
                                    <div style="text-align: right; padding: 0 1rem;">
                                        <div style="font-weight: 700; color: var(--primary-blue); font-size: 1.25rem;" data-testid="text-user-balance-${index}">
                                            ${user.account ? '$' + user.account.balance.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 }) : 'N/A'}
                                        </div>
                                        <div style="color: var(--text-secondary); font-size: 0.8rem;">Available: ${user.account ? '$' + user.account.available.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 }) : 'N/A'}</div>
                                    </div>
                                </div>
                                <div style="display: flex; gap: 0.5rem; flex-wrap: wrap;">
                                    ${!user.isAdmin ? `
                                        <button onclick="openAdjustFundsModal('${user.email}', '${user.name}', ${user.account?.balance || 0}, 'add')" style="background: #10b981; color: white; border: none; padding: 0.5rem 0.75rem; border-radius: 8px; font-weight: 600; cursor: pointer; font-size: 0.85rem; display: flex; align-items: center; gap: 0.25rem;" data-testid="button-add-funds-${index}">
                                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="12" y1="5" x2="12" y2="19"></line><line x1="5" y1="12" x2="19" y2="12"></line></svg>
                                            Add
                                        </button>
                                        <button onclick="openAdjustFundsModal('${user.email}', '${user.name}', ${user.account?.balance || 0}, 'reduce')" style="background: #ef4444; color: white; border: none; padding: 0.5rem 0.75rem; border-radius: 8px; font-weight: 600; cursor: pointer; font-size: 0.85rem; display: flex; align-items: center; gap: 0.25rem;" data-testid="button-reduce-funds-${index}">
                                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="5" y1="12" x2="19" y2="12"></line></svg>
                                            Reduce
                                        </button>
                                        ${user.blocked 
                                            ? `<button onclick="toggleBlockUser('${user.email}', false)" style="background: #3b82f6; color: white; border: none; padding: 0.5rem 0.75rem; border-radius: 8px; font-weight: 600; cursor: pointer; font-size: 0.85rem;" data-testid="button-unblock-${index}">Unblock</button>`
                                            : `<button onclick="toggleBlockUser('${user.email}', true)" style="background: #f59e0b; color: white; border: none; padding: 0.5rem 0.75rem; border-radius: 8px; font-weight: 600; cursor: pointer; font-size: 0.85rem;" data-testid="button-block-${index}">Block</button>`
                                        }
                                        <button onclick="deleteUser('${user.email}', '${user.name}')" style="background: none; border: 2px solid #ef4444; color: #ef4444; padding: 0.5rem 0.75rem; border-radius: 8px; font-weight: 600; cursor: pointer; font-size: 0.85rem;" data-testid="button-delete-${index}">
                                            Delete
                                        </button>
                                    ` : '<span style="color: var(--text-secondary); font-style: italic;">Protected admin account</span>'}
                                </div>
                            </div>
                        `).join('')}
                    </div>
                </div>

                <div id="adjustFundsModal" style="display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0, 0, 0, 0.5); z-index: 2000; align-items: center; justify-content: center;" data-testid="modal-adjust-funds">
                    <div style="background: white; padding: 2rem; border-radius: 16px; max-width: 450px; width: 90%;">
                        <div style="display: flex; align-items: center; gap: 1rem; margin-bottom: 1.5rem;">
                            <div id="modalIcon" style="width: 48px; height: 48px; border-radius: 12px; display: flex; align-items: center; justify-content: center;"></div>
                            <div>
                                <h3 id="modalTitle" style="font-size: 1.5rem; font-weight: 700; color: var(--dark-gray); margin: 0;" data-testid="text-modal-title"></h3>
                                <div id="modalUserName" style="color: var(--text-secondary);" data-testid="text-modal-user"></div>
                            </div>
                        </div>
                        
                        <div style="background: var(--light-gray); padding: 1rem; border-radius: 8px; margin-bottom: 1.5rem;">
                            <div style="display: flex; justify-content: space-between; align-items: center;">
                                <span style="color: var(--text-secondary);">Current Balance</span>
                                <span id="currentBalance" style="font-weight: 700; font-size: 1.25rem; color: var(--primary-blue);"></span>
                            </div>
                        </div>
                        
                        <div style="margin-bottom: 1.5rem;">
                            <label style="display: block; font-weight: 600; color: var(--dark-gray); margin-bottom: 0.5rem;">Amount ($)</label>
                            <input type="number" id="adjustAmount" min="0.01" step="0.01" placeholder="Enter amount" style="width: 100%; padding: 0.75rem; border: 2px solid var(--border-color); border-radius: 8px; font-size: 1.1rem;" data-testid="input-adjust-amount">
                            <div id="newBalancePreview" style="margin-top: 0.5rem; color: var(--text-secondary); font-size: 0.9rem;"></div>
                        </div>
                        
                        <div style="display: flex; gap: 0.75rem;">
                            <button onclick="closeAdjustFundsModal()" style="flex: 1; background: var(--light-gray); color: var(--dark-gray); padding: 0.875rem; border: none; border-radius: 8px; font-weight: 600; cursor: pointer; font-size: 1rem;" data-testid="button-cancel-adjust">Cancel</button>
                            <button id="confirmAdjustBtn" onclick="confirmAdjustFunds()" style="flex: 1; padding: 0.875rem; border: none; border-radius: 8px; font-weight: 600; cursor: pointer; font-size: 1rem;" data-testid="button-confirm-adjust"></button>
                        </div>
                    </div>
                </div>
            `;

            const adjustAmountInput = document.getElementById('adjustAmount');
            if (adjustAmountInput) {
                adjustAmountInput.addEventListener('input', updateNewBalancePreview);
            }
        } catch (error) {
            console.error('Error loading users:', error);
            pageContainer.innerHTML = '<div style="text-align: center; padding: 3rem; color: #ef4444;">Failed to load users</div>';
        }
    }

    let selectedUserEmail = '';
    let adjustMode = 'add';
    let currentUserBalance = 0;

    window.openAdjustFundsModal = function(email, name, balance, mode) {
        selectedUserEmail = email;
        adjustMode = mode;
        currentUserBalance = balance;

        const modal = document.getElementById('adjustFundsModal');
        const modalIcon = document.getElementById('modalIcon');
        const modalTitle = document.getElementById('modalTitle');
        const modalUserName = document.getElementById('modalUserName');
        const currentBalanceEl = document.getElementById('currentBalance');
        const confirmBtn = document.getElementById('confirmAdjustBtn');
        const amountInput = document.getElementById('adjustAmount');

        modalUserName.textContent = `${name} (${email})`;
        currentBalanceEl.textContent = '$' + balance.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
        amountInput.value = '';
        document.getElementById('newBalancePreview').textContent = '';

        if (mode === 'add') {
            modalIcon.style.background = '#d1fae5';
            modalIcon.innerHTML = '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#10b981" stroke-width="2"><line x1="12" y1="5" x2="12" y2="19"></line><line x1="5" y1="12" x2="19" y2="12"></line></svg>';
            modalTitle.textContent = 'Add Funds';
            confirmBtn.style.background = '#10b981';
            confirmBtn.style.color = 'white';
            confirmBtn.textContent = 'Add Funds';
        } else {
            modalIcon.style.background = '#fee2e2';
            modalIcon.innerHTML = '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#ef4444" stroke-width="2"><line x1="5" y1="12" x2="19" y2="12"></line></svg>';
            modalTitle.textContent = 'Reduce Funds';
            confirmBtn.style.background = '#ef4444';
            confirmBtn.style.color = 'white';
            confirmBtn.textContent = 'Reduce Funds';
        }

        modal.style.display = 'flex';
    };

    function updateNewBalancePreview() {
        const amount = parseFloat(document.getElementById('adjustAmount').value) || 0;
        const previewEl = document.getElementById('newBalancePreview');
        
        if (amount > 0) {
            let newBalance;
            if (adjustMode === 'add') {
                newBalance = currentUserBalance + amount;
                previewEl.innerHTML = `New balance: <strong style="color: #10b981;">$${newBalance.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}</strong> (+$${amount.toFixed(2)})`;
            } else {
                newBalance = currentUserBalance - amount;
                if (newBalance < 0) {
                    previewEl.innerHTML = `<span style="color: #ef4444;">Cannot reduce below $0.00</span>`;
                } else {
                    previewEl.innerHTML = `New balance: <strong style="color: #ef4444;">$${newBalance.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}</strong> (-$${amount.toFixed(2)})`;
                }
            }
        } else {
            previewEl.textContent = '';
        }
    }

    window.closeAdjustFundsModal = function() {
        document.getElementById('adjustFundsModal').style.display = 'none';
        selectedUserEmail = '';
        adjustMode = 'add';
        currentUserBalance = 0;
    };

    window.confirmAdjustFunds = async function() {
        const inputAmount = parseFloat(document.getElementById('adjustAmount').value);
        
        if (!inputAmount || inputAmount <= 0) {
            alert('Please enter a valid amount');
            return;
        }

        const amount = adjustMode === 'add' ? inputAmount : -inputAmount;

        if (adjustMode === 'reduce' && currentUserBalance + amount < 0) {
            alert('Cannot reduce funds below $0.00');
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
                const action = adjustMode === 'add' ? 'added to' : 'reduced from';
                alert(`Successfully ${adjustMode === 'add' ? 'added' : 'reduced'} $${inputAmount.toFixed(2)} ${adjustMode === 'add' ? 'to' : 'from'} the account.\n\nNew balance: $${data.new_balance.toFixed(2)}`);
                closeAdjustFundsModal();
                await loadUsersPage();
            } else {
                alert(data.error || 'Failed to adjust funds');
            }
        } catch (error) {
            console.error('Adjust funds error:', error);
            alert('An error occurred while adjusting funds');
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
                    <h1 class="page-title" data-testid="text-page-title">CyberGuardAI</h1>
                    <p class="page-subtitle" data-testid="text-page-subtitle">AI-Powered Threat Detection & Analysis Engine</p>
                </div>

                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 2rem;">
                    <div style="background: ${statusData.ai_enabled ? '#d1fae5' : '#fed7aa'}; padding: 1.5rem; border-radius: 12px;">
                        <div style="font-size: 0.9rem; color: var(--dark-gray); margin-bottom: 0.5rem; font-weight: 600;">Groq API</div>
                        <div style="font-size: 1.5rem; font-weight: 700; color: ${statusData.ai_enabled ? '#10b981' : '#ea580c'};" data-testid="status-ai">
                            ${statusData.ai_enabled ? 'Active' : 'Inactive'}
                        </div>
                    </div>
                    <div style="background: #d1fae5; padding: 1.5rem; border-radius: 12px;">
                        <div style="font-size: 0.9rem; color: var(--dark-gray); margin-bottom: 0.5rem; font-weight: 600;">Local Detection</div>
                        <div style="font-size: 1.5rem; font-weight: 700; color: #10b981;" data-testid="status-local">Active</div>
                    </div>
                    <div style="background: #dbeafe; padding: 1.5rem; border-radius: 12px;">
                        <div style="font-size: 0.9rem; color: var(--dark-gray); margin-bottom: 0.5rem; font-weight: 600;">Threats Detected</div>
                        <div style="font-size: 1.5rem; font-weight: 700; color: #3b82f6;" data-testid="count-threats">${statusData.total_threats_detected}</div>
                    </div>
                    <div style="background: #d1fae5; padding: 1.5rem; border-radius: 12px;">
                        <div style="font-size: 0.9rem; color: var(--dark-gray); margin-bottom: 0.5rem; font-weight: 600;">Protection Status</div>
                        <div style="font-size: 1.5rem; font-weight: 700; color: #10b981;" data-testid="status-protection">Active</div>
                    </div>
                </div>

                ${!statusData.ai_enabled ? `
                <div style="background: #fef3c7; border-left: 4px solid #f59e0b; padding: 1.5rem; border-radius: 8px; margin-bottom: 2rem;">
                    <div style="font-weight: 700; color: #92400e; margin-bottom: 0.5rem;">Groq AI Not Configured</div>
                    <div style="color: #78350f; font-size: 0.95rem;">
                        To enable advanced AI-powered threat detection, set your GROQ_API_KEY environment variable. 
                        Get your API key from <a href="https://console.groq.com" target="_blank" style="color: #0052CC; font-weight: 600;">Groq Console</a>.
                    </div>
                </div>
                ` : ''}

                <div style="background: white; padding: 2rem; border-radius: 16px; box-shadow: 0 4px 20px rgba(0, 0, 0, 0.08); margin-bottom: 2rem;">
                    <h2 style="font-size: 1.5rem; font-weight: 700; margin-bottom: 1rem; color: var(--dark-gray);" data-testid="text-analyzer-title">Real-Time Threat Analyzer</h2>
                    <p style="color: var(--text-secondary); margin-bottom: 1.5rem;">Analyze text for SQL injection, XSS, command injection, and other security threats.</p>
                    
                    <div style="margin-bottom: 1rem;">
                        <label style="display: block; font-weight: 600; color: var(--dark-gray); margin-bottom: 0.5rem;">Text to Analyze</label>
                        <textarea id="analyzeText" placeholder="Enter any text, code, or input to analyze for security threats..." style="width: 100%; min-height: 150px; padding: 1rem; border: 2px solid var(--border-color); border-radius: 8px; font-size: 1rem; font-family: monospace; resize: vertical;" data-testid="input-analyze-text"></textarea>
                    </div>
                    
                    <button onclick="analyzeText()" style="background: var(--primary-blue); color: white; border: none; padding: 0.875rem 2rem; border-radius: 8px; font-weight: 600; cursor: pointer; font-size: 1rem;" data-testid="button-analyze">
                        Analyze for Threats
                    </button>

                    <div id="analysisResult" style="margin-top: 1.5rem; display: none;" data-testid="container-analysis-result"></div>
                </div>

                <div style="background: white; padding: 2rem; border-radius: 16px; box-shadow: 0 4px 20px rgba(0, 0, 0, 0.08);">
                    <h2 style="font-size: 1.5rem; font-weight: 700; margin-bottom: 1rem; color: var(--dark-gray);" data-testid="text-history-title">Threat Detection History</h2>
                    
                    ${threatsData.threats.length === 0 ? `
                        <div style="text-align: center; padding: 3rem; color: var(--text-secondary);">
                            <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" style="margin: 0 auto 1rem;"><circle cx="12" cy="12" r="10"></circle><path d="M8 14s1.5 2 4 2 4-2 4-2"></path><line x1="9" y1="9" x2="9.01" y2="9"></line><line x1="15" y1="9" x2="15.01" y2="9"></line></svg>
                            <div style="font-size: 1.1rem; font-weight: 600;">No threats detected yet!</div>
                            <div style="font-size: 0.95rem; margin-top: 0.5rem;">Your system is secure.</div>
                        </div>
                    ` : `
                        <div style="overflow-x: auto; max-height: 500px; overflow-y: auto;">
                            ${threatsData.threats.map((threat, index) => `
                                <div style="border: 2px solid ${getThreatColor(threat.analysis.severity)}; border-radius: 12px; padding: 1.5rem; margin-bottom: 1rem; background: ${getThreatBgColor(threat.analysis.severity)};" data-testid="card-threat-${index}">
                                    <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 1rem; gap: 1rem; flex-wrap: wrap;">
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
                                        <span style="font-size: 0.8rem; color: var(--text-secondary);">Detection Source: ${threat.source === 'groq_ai' ? 'Groq AI' : 'Local Detection'}</span>
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

        resultDiv.innerHTML = '<div style="text-align: center; padding: 2rem; color: var(--text-secondary);">Analyzing...</div>';
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
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem; gap: 1rem; flex-wrap: wrap;">
                            <div style="font-weight: 700; font-size: 1.2rem; color: var(--dark-gray);">
                                ${analysis.threat_detected ? 'Threat Detected' : 'No Threats Found'}
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
                                Detection Source: ${data.source === 'groq_ai' ? 'Groq AI (Advanced)' : 'Local Detection (Basic)'}
                            </span>
                        </div>
                    </div>
                `;
                
                await updateAlertBadge();
            } else {
                resultDiv.innerHTML = '<div style="padding: 1.5rem; background: #fee2e2; border-radius: 8px; color: #dc2626;">Error: ' + (data.error || 'Analysis failed') + '</div>';
            }
        } catch (error) {
            console.error('Analysis error:', error);
            resultDiv.innerHTML = '<div style="padding: 1.5rem; background: #fee2e2; border-radius: 8px; color: #dc2626;">Network error occurred</div>';
        }
    };

    async function loadDatabasePage() {
        try {
            const token = localStorage.getItem('authToken');
            const response = await fetch('/api/admin/database/stats', {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            const stats = await response.json();

            const clearableTables = [
                { name: 'login_logs', label: 'Login Logs', count: stats.login_logs_count, icon: 'key', desc: 'User login attempts and authentication history' },
                { name: 'security_events', label: 'Security Events', count: stats.security_events_count, icon: 'shield', desc: 'Security incidents and threat detections' },
                { name: 'threat_detections', label: 'Threat Detections', count: stats.threat_detections_count, icon: 'alert', desc: 'Analyzed threats and patterns' },
                { name: 'ai_alerts', label: 'AI Alerts', count: stats.ai_alerts_count, icon: 'bell', desc: 'AI-generated security alerts' }
            ];

            const protectedTables = [
                { name: 'users', label: 'Users', count: stats.users_count, icon: 'users', desc: 'User accounts (protected)' },
                { name: 'accounts', label: 'Accounts', count: stats.accounts_count, icon: 'wallet', desc: 'Financial accounts (protected)' },
                { name: 'transactions', label: 'Transactions', count: stats.transactions_count, icon: 'money', desc: 'Transaction history (protected)' },
                { name: 'active_tokens', label: 'Active Sessions', count: stats.active_tokens_count, icon: 'lock', desc: 'Active login sessions' }
            ];

            pageContainer.innerHTML = `
                <div class="page-header">
                    <h1 class="page-title" data-testid="text-page-title">Database Manager</h1>
                    <p class="page-subtitle" data-testid="text-page-subtitle">View and manage database records</p>
                </div>

                <div style="background: #fef3c7; border-left: 4px solid #f59e0b; padding: 1rem 1.5rem; border-radius: 8px; margin-bottom: 2rem;">
                    <div style="display: flex; align-items: center; gap: 0.75rem;">
                        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#f59e0b" stroke-width="2">
                            <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path>
                            <line x1="12" y1="9" x2="12" y2="13"></line>
                            <line x1="12" y1="17" x2="12.01" y2="17"></line>
                        </svg>
                        <div>
                            <div style="font-weight: 600; color: #92400e;">Important Notice</div>
                            <div style="color: #78350f; font-size: 0.9rem;">Only log and alert tables can be cleared. User data, accounts, and transactions are protected.</div>
                        </div>
                    </div>
                </div>

                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 1.5rem; margin-bottom: 2rem;">
                    <div style="background: white; padding: 1.5rem; border-radius: 16px; box-shadow: 0 4px 20px rgba(0, 0, 0, 0.08);">
                        <h2 style="font-size: 1.25rem; font-weight: 700; margin-bottom: 1rem; color: var(--dark-gray); display: flex; align-items: center; gap: 0.5rem;" data-testid="text-clearable-title">
                            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <path d="M3 6h18"></path><path d="M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6"></path>
                                <path d="M8 6V4a2 2 0 012-2h4a2 2 0 012 2v2"></path>
                            </svg>
                            Clearable Tables
                        </h2>
                        <div style="display: grid; gap: 0.75rem;">
                            ${clearableTables.map((table, index) => `
                                <div style="display: flex; justify-content: space-between; align-items: center; padding: 1rem; background: var(--light-gray); border-radius: 8px;" data-testid="card-table-${table.name}">
                                    <div>
                                        <div style="font-weight: 600; color: var(--dark-gray);">${table.label}</div>
                                        <div style="font-size: 0.8rem; color: var(--text-secondary);">${table.desc}</div>
                                    </div>
                                    <div style="display: flex; align-items: center; gap: 0.75rem;">
                                        <span style="background: var(--primary-blue); color: white; padding: 0.25rem 0.75rem; border-radius: 8px; font-weight: 600;" data-testid="count-${table.name}">${table.count}</span>
                                        <button onclick="viewTableData('${table.name}')" style="background: #3b82f6; color: white; border: none; padding: 0.5rem 0.75rem; border-radius: 6px; cursor: pointer; font-size: 0.8rem;" data-testid="button-view-${table.name}">
                                            View
                                        </button>
                                        <button onclick="clearTableData('${table.name}')" style="background: #ef4444; color: white; border: none; padding: 0.5rem 0.75rem; border-radius: 6px; cursor: pointer; font-size: 0.8rem;" data-testid="button-clear-${table.name}" ${table.count === 0 ? 'disabled style="opacity: 0.5; cursor: not-allowed;"' : ''}>
                                            Clear
                                        </button>
                                    </div>
                                </div>
                            `).join('')}
                        </div>
                        
                        <div style="margin-top: 1.5rem; padding-top: 1.5rem; border-top: 2px solid var(--border-color);">
                            <div style="display: flex; justify-content: space-between; align-items: center; gap: 1rem; flex-wrap: wrap;">
                                <div>
                                    <div style="font-weight: 600; color: var(--dark-gray);">Clear Old Logs</div>
                                    <div style="font-size: 0.8rem; color: var(--text-secondary);">Remove logs older than specified days</div>
                                </div>
                                <div style="display: flex; align-items: center; gap: 0.5rem;">
                                    <input type="number" id="clearDays" value="30" min="1" max="365" style="width: 80px; padding: 0.5rem; border: 2px solid var(--border-color); border-radius: 6px; text-align: center;" data-testid="input-clear-days">
                                    <span style="color: var(--text-secondary);">days</span>
                                    <button onclick="clearOldLogs()" style="background: #f59e0b; color: white; border: none; padding: 0.5rem 1rem; border-radius: 6px; cursor: pointer; font-weight: 600;" data-testid="button-clear-old">
                                        Clear Old
                                    </button>
                                </div>
                            </div>
                        </div>
                    </div>

                    <div style="background: white; padding: 1.5rem; border-radius: 16px; box-shadow: 0 4px 20px rgba(0, 0, 0, 0.08);">
                        <h2 style="font-size: 1.25rem; font-weight: 700; margin-bottom: 1rem; color: var(--dark-gray); display: flex; align-items: center; gap: 0.5rem;" data-testid="text-protected-title">
                            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
                            </svg>
                            Protected Tables
                        </h2>
                        <div style="display: grid; gap: 0.75rem;">
                            ${protectedTables.map((table, index) => `
                                <div style="display: flex; justify-content: space-between; align-items: center; padding: 1rem; background: #f0fdf4; border-radius: 8px; border: 1px solid #bbf7d0;" data-testid="card-protected-${table.name}">
                                    <div>
                                        <div style="font-weight: 600; color: var(--dark-gray); display: flex; align-items: center; gap: 0.5rem;">
                                            ${table.label}
                                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#16a34a" stroke-width="2">
                                                <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
                                                <path d="M7 11V7a5 5 0 0110 0v4"></path>
                                            </svg>
                                        </div>
                                        <div style="font-size: 0.8rem; color: var(--text-secondary);">${table.desc}</div>
                                    </div>
                                    <span style="background: #16a34a; color: white; padding: 0.25rem 0.75rem; border-radius: 8px; font-weight: 600;" data-testid="count-protected-${table.name}">${table.count}</span>
                                </div>
                            `).join('')}
                        </div>
                    </div>
                </div>

                <div id="tableDataViewer" style="display: none; background: white; padding: 2rem; border-radius: 16px; box-shadow: 0 4px 20px rgba(0, 0, 0, 0.08);" data-testid="container-table-viewer">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5rem;">
                        <h2 id="tableViewerTitle" style="font-size: 1.5rem; font-weight: 700; color: var(--dark-gray);"></h2>
                        <button onclick="closeTableViewer()" style="background: var(--light-gray); border: none; padding: 0.5rem 1rem; border-radius: 6px; cursor: pointer; font-weight: 600;" data-testid="button-close-viewer">
                            Close
                        </button>
                    </div>
                    <div id="tableDataContent" style="overflow-x: auto; max-height: 500px; overflow-y: auto;"></div>
                </div>
            `;
        } catch (error) {
            console.error('Error loading database page:', error);
            pageContainer.innerHTML = '<div style="text-align: center; padding: 3rem; color: #ef4444;">Failed to load database manager</div>';
        }
    }

    window.viewTableData = async function(tableName) {
        try {
            const token = localStorage.getItem('authToken');
            const response = await fetch(`/api/admin/database/table/${tableName}?limit=50`, {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            const result = await response.json();

            const viewer = document.getElementById('tableDataViewer');
            const title = document.getElementById('tableViewerTitle');
            const content = document.getElementById('tableDataContent');

            title.textContent = tableName.split('_').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' ') + ` (${result.data.length} records)`;

            if (result.data.length === 0) {
                content.innerHTML = '<div style="text-align: center; padding: 2rem; color: var(--text-secondary);">No records found</div>';
            } else {
                const columns = Object.keys(result.data[0]);
                content.innerHTML = `
                    <table style="width: 100%; border-collapse: collapse; font-size: 0.85rem;">
                        <thead style="background: var(--light-gray); position: sticky; top: 0;">
                            <tr>
                                ${columns.map(col => `<th style="text-align: left; padding: 0.75rem; font-weight: 600; white-space: nowrap;">${col}</th>`).join('')}
                            </tr>
                        </thead>
                        <tbody>
                            ${result.data.map((row, index) => `
                                <tr style="border-bottom: 1px solid var(--border-color);">
                                    ${columns.map(col => {
                                        let value = row[col];
                                        if (typeof value === 'object' && value !== null) {
                                            value = JSON.stringify(value).substring(0, 100) + '...';
                                        }
                                        if (typeof value === 'string' && value.length > 100) {
                                            value = value.substring(0, 100) + '...';
                                        }
                                        return `<td style="padding: 0.75rem; max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${value !== null ? value : 'null'}</td>`;
                                    }).join('')}
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                `;
            }

            viewer.style.display = 'block';
            viewer.scrollIntoView({ behavior: 'smooth' });
        } catch (error) {
            console.error('Error viewing table data:', error);
            alert('Failed to load table data');
        }
    };

    window.closeTableViewer = function() {
        document.getElementById('tableDataViewer').style.display = 'none';
    };

    window.clearTableData = async function(tableName) {
        const tableLabel = tableName.split('_').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' ');
        
        if (!confirm(`Are you sure you want to clear ALL records from "${tableLabel}"?\n\nThis action cannot be undone.`)) {
            return;
        }

        if (!confirm(`FINAL WARNING: This will permanently delete all data from "${tableLabel}". Continue?`)) {
            return;
        }

        try {
            const token = localStorage.getItem('authToken');
            const response = await fetch(`/api/admin/database/clear/${tableName}`, {
                method: 'DELETE',
                headers: { 'Authorization': `Bearer ${token}` }
            });

            const result = await response.json();

            if (response.ok) {
                alert(result.message);
                await loadDatabasePage();
            } else {
                alert('Error: ' + (result.error || 'Failed to clear table'));
            }
        } catch (error) {
            console.error('Error clearing table:', error);
            alert('Network error occurred');
        }
    };

    window.clearOldLogs = async function() {
        const daysInput = document.getElementById('clearDays');
        const days = parseInt(daysInput.value);
        
        if (!days || days < 1) {
            alert('Please enter a valid number of days (minimum 1)');
            return;
        }

        if (!confirm(`Clear all logs older than ${days} days?\n\nThis will affect login logs, security events, threat detections, and dismissed AI alerts.`)) {
            return;
        }

        try {
            const token = localStorage.getItem('authToken');
            const response = await fetch('/api/admin/database/clear-old', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`
                },
                body: JSON.stringify({ days: days })
            });

            const result = await response.json();
            console.log('Clear old logs result:', result);

            if (response.ok && result.success) {
                alert(`Cleared ${result.total_cleared} old records:\n- Login Logs: ${result.cleared.login_logs}\n- Security Events: ${result.cleared.security_events}\n- Threat Detections: ${result.cleared.threat_detections}\n- AI Alerts: ${result.cleared.ai_alerts}`);
                await loadDatabasePage();
            } else {
                alert('Error: ' + (result.error || 'Failed to clear old logs'));
            }
        } catch (error) {
            console.error('Error clearing old logs:', error);
            alert('Network error occurred: ' + error.message);
        }
    };
});
