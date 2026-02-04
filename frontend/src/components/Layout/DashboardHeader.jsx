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
