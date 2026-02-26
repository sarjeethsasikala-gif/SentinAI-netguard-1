import { useState, useEffect } from 'react';
import api from '../api/axiosConfig';

export const useAuth = () => {
    const [isAuthenticated, setIsAuthenticated] = useState(false);
    const [userRole, setUserRole] = useState('SOC Analyst');
    const [username, setUsername] = useState('');

    // Init auth state from local storage
    useEffect(() => {
        const token = localStorage.getItem('token');
        if (token) {
            try {
                const payload = JSON.parse(atob(token.split('.')[1]));
                // Check expiry
                if (payload.exp * 1000 < Date.now()) {
                    throw new Error('Token expired');
                }
                setIsAuthenticated(true);
                setUserRole(payload.role || 'SOC Analyst');
                setUsername(payload.sub || '');
                api.defaults.headers.common['Authorization'] = `Bearer ${token}`;
            } catch (e) {
                localStorage.removeItem('token');
                setIsAuthenticated(false);
            }
        }
    }, []);

    const login = async (username, password) => {
        try {
            // Point to Python Backend via proxy
            const res = await api.post('/auth/login', { username, password });
            const { access_token } = res.data;

            localStorage.setItem('token', access_token);
            api.defaults.headers.common['Authorization'] = `Bearer ${access_token}`;

            const payload = JSON.parse(atob(access_token.split('.')[1]));
            setIsAuthenticated(true);
            setUserRole(payload.role || 'SOC Analyst');
            setUsername(payload.sub || '');
            return true;
        } catch (error) {
            console.error("Auth Error:", error);
            return false;
        }
    };

    const logout = () => {
        localStorage.removeItem('token');
        delete api.defaults.headers.common['Authorization'];
        setIsAuthenticated(false);
        setUserRole('SOC Analyst');
    };

    const toggleRole = () => {
        // In real auth, role is tied to user. 
        // We keep this for now but it won't persist across reloads unless we update the token (complex).
        // Let's just switch the local view state.
        setUserRole(prev => prev === 'SOC Analyst' ? 'CISO' : 'SOC Analyst');
    };

    return {
        isAuthenticated,
        userRole,
        username,
        login,
        logout,
        toggleRole
    };
};
