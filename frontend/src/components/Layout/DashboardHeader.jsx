import { ShieldAlert, User, UserCog, LogOut, Lock } from 'lucide-react'
import NotificationCenter from '../NotificationCenter'
import ThemeToggle from '../ThemeToggle'

const DashboardHeader = ({ theme, userRole, criticalAlerts, actions, children }) => {
    return (
        <header className="header">
            <div className="logo">
                <ShieldAlert size={32} color={theme === 'dark' ? "#38BDF8" : "#0969DA"} />
                <h1>Sentin<span style={{ color: 'var(--accent)' }}>AI</span> NetGuard</h1>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '15px' }}>
                {/* Custom Controls (Date Picker / PDF) */}
                {children}

                <NotificationCenter alerts={criticalAlerts} onResolve={actions.resolveThreat} />
                <ThemeToggle theme={theme} toggleTheme={actions.toggleTheme} />

                <div className="role-toggle" onClick={actions.toggleRole}>
                    {userRole === 'SOC Analyst' ? <User size={18} /> : <UserCog size={18} />}
                    <span>{userRole} View</span>
                </div>

                <div className="status-badge">
                    <div className="pulse-icon" style={{ width: 8, height: 8, borderRadius: '50%', background: 'var(--success)' }}></div>
                    <span>System Active</span>
                </div>

                <div className="mode-toggle" onClick={actions.toggleStorageMode} style={{
                    cursor: 'pointer',
                    padding: '4px 8px',
                    borderRadius: '4px',
                    border: '1px solid var(--border)',
                    fontSize: '0.8rem',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px',
                    background: actions.storageMode === 'cloud' ? 'rgba(9, 105, 218, 0.1)' : 'rgba(255, 171, 0, 0.1)'
                }}>
                    <div style={{
                        width: 8, height: 8, borderRadius: '50%',
                        background: actions.storageMode === 'cloud' ? 'var(--primary)' : 'orange'
                    }}></div>
                    <span>{actions.storageMode === 'cloud' ? 'Cloud DB' : 'Local DB'}</span>
                </div>

                <div style={{ width: '1px', height: '24px', background: 'var(--border)', margin: '0 5px' }}></div>

                <button onClick={actions.openPasswordModal} className="action-btn" title="Change Password" style={{ color: 'var(--text-secondary)', borderColor: 'var(--border)' }}>
                    <Lock size={16} />
                </button>

                <button onClick={actions.logout} className="action-btn" title="Logout" style={{ color: 'var(--critical)', border: '1px solid var(--critical)' }}>
                    <LogOut size={16} />
                </button>
            </div>
        </header>
    )
}

export default DashboardHeader
