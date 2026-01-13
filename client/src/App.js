import React, { useState, useEffect } from 'react';
import './App.css';

const API_URL = 'http://localhost:5001/api';

function App() {
    const [isAuthenticated, setIsAuthenticated] = useState(false);
    const [token, setToken] = useState(localStorage.getItem('token') || '');
    const [user, setUser] = useState(null);
    const [activeTab, setActiveTab] = useState('addresses');
    const [isLogin, setIsLogin] = useState(true);
    const [authForm, setAuthForm] = useState({ email: '', password: '', name: '' });
    const [addressForm, setAddressForm] = useState({ label: '', street: '', city: '', state: '', postal_code: '', country: '' });
    const [nominationForm, setNominationForm] = useState({ nominee_id: '', reason: '' });
    const [addresses, setAddresses] = useState([]);
    const [users, setUsers] = useState([]);
    const [nominationsGiven, setNominationsGiven] = useState([]);
    const [nominationsReceived, setNominationsReceived] = useState([]);
    const [allNominations, setAllNominations] = useState([]);
    const [loading, setLoading] = useState(false);
    const [message, setMessage] = useState({ type: '', text: '' });
    const [editingAddress, setEditingAddress] = useState(null);
    const [addressHistory, setAddressHistory] = useState([]);
    const [showHistory, setShowHistory] = useState(false);

    useEffect(() => {
        if (token) {
            setIsAuthenticated(true);
            const savedUser = localStorage.getItem('user');
            if (savedUser) setUser(JSON.parse(savedUser));
            fetchAllData();
        }
    }, [token]);

    const apiCall = async (endpoint, method = 'GET', body = null) => {
        const options = {
            method,
            headers: {
                'Content-Type': 'application/json',
                ...(token && { 'Authorization': `Bearer ${token}` })
            }
        };
        if (body) options.body = JSON.stringify(body);
        const response = await fetch(`${API_URL}${endpoint}`, options);
        return response.json();
    };

    const fetchAllData = async () => {
        try {
            const [addressRes, usersRes, givenRes, receivedRes, allRes] = await Promise.all([
                apiCall('/addresses'),
                apiCall('/users'),
                apiCall('/nominations/given'),
                apiCall('/nominations/received'),
                apiCall('/nominations/all')
            ]);
            if (addressRes.success) setAddresses(addressRes.addresses);
            if (usersRes.success) setUsers(usersRes.users);
            if (givenRes.success) setNominationsGiven(givenRes.nominations);
            if (receivedRes.success) setNominationsReceived(receivedRes.nominations);
            if (allRes.success) setAllNominations(allRes.nominations);
        } catch (error) {
            console.error('Fetch error:', error);
        }
    };

    const handleAuth = async (e) => {
        e.preventDefault();
        setLoading(true);
        setMessage({ type: '', text: '' });
        try {
            const endpoint = isLogin ? '/login' : '/register';
            const data = await apiCall(endpoint, 'POST', authForm);
            if (data.success) {
                setToken(data.token);
                setUser(data.user);
                localStorage.setItem('token', data.token);
                localStorage.setItem('user', JSON.stringify(data.user));
                setIsAuthenticated(true);
                setMessage({ type: 'success', text: data.message });
            } else {
                setMessage({ type: 'error', text: data.message });
            }
        } catch (error) {
            setMessage({ type: 'error', text: 'Connection failed. Please try again.' });
        } finally {
            setLoading(false);
        }
    };

    const handleLogout = () => {
        setToken('');
        setUser(null);
        setIsAuthenticated(false);
        localStorage.removeItem('token');
        localStorage.removeItem('user');
        setAuthForm({ email: '', password: '', name: '' });
    };

    const handleAddAddress = async (e) => {
        e.preventDefault();
        setLoading(true);
        try {
            const data = await apiCall('/addresses', 'POST', addressForm);
            if (data.success) {
                setAddresses([data.address, ...addresses]);
                setAddressForm({ label: '', street: '', city: '', state: '', postal_code: '', country: '' });
                setMessage({ type: 'success', text: 'Address added!' });
                fetchAddressHistory();
            } else {
                setMessage({ type: 'error', text: data.message });
            }
        } catch (error) {
            setMessage({ type: 'error', text: 'Failed to add address' });
        } finally {
            setLoading(false);
        }
    };

    const handleUpdateAddress = async (e) => {
        e.preventDefault();
        setLoading(true);
        try {
            const data = await apiCall(`/addresses/${editingAddress.id}`, 'PUT', addressForm);
            if (data.success) {
                setAddresses(addresses.map(a => a.id === editingAddress.id ? data.address : a));
                setAddressForm({ label: '', street: '', city: '', state: '', postal_code: '', country: '' });
                setEditingAddress(null);
                setMessage({ type: 'success', text: 'Address updated! Change tracked in history.' });
                fetchAddressHistory();
            } else {
                setMessage({ type: 'error', text: data.message });
            }
        } catch (error) {
            setMessage({ type: 'error', text: 'Failed to update address' });
        } finally {
            setLoading(false);
        }
    };

    const startEditAddress = (addr) => {
        setEditingAddress(addr);
        setAddressForm({
            label: addr.label,
            street: addr.street,
            city: addr.city,
            state: addr.state || '',
            postal_code: addr.postal_code || '',
            country: addr.country
        });
    };

    const cancelEdit = () => {
        setEditingAddress(null);
        setAddressForm({ label: '', street: '', city: '', state: '', postal_code: '', country: '' });
    };

    const handleDeleteAddress = async (id) => {
        try {
            const data = await apiCall(`/addresses/${id}`, 'DELETE');
            if (data.success) {
                setAddresses(addresses.filter(a => a.id !== id));
                setMessage({ type: 'success', text: 'Address deleted! History preserved.' });
                fetchAddressHistory();
            }
        } catch (error) {
            console.error('Delete error:', error);
        }
    };

    const fetchAddressHistory = async () => {
        try {
            const data = await apiCall('/addresses/history');
            if (data.success) setAddressHistory(data.history);
        } catch (error) {
            console.error('History fetch error:', error);
        }
    };

    const handleNominate = async (e) => {
        e.preventDefault();
        setLoading(true);
        try {
            const data = await apiCall('/nominations', 'POST', nominationForm);
            if (data.success) {
                setNominationForm({ nominee_id: '', reason: '' });
                setMessage({ type: 'success', text: 'Nomination submitted!' });
                fetchAllData();
            } else {
                setMessage({ type: 'error', text: data.message });
            }
        } catch (error) {
            setMessage({ type: 'error', text: 'Failed to submit nomination' });
        } finally {
            setLoading(false);
        }
    };

    if (!isAuthenticated) {
        return (
            <div className="app">
                <div className="ambient-glow ambient-glow-1"></div>
                <div className="ambient-glow ambient-glow-2"></div>
                <div className="container">
                    <header className="header">
                        <div className="badge">
                            <span className="badge-dot"></span>
                            Secure System
                        </div>
                        <h1 className="title">{isLogin ? 'Welcome Back' : 'Create Account'}</h1>
                        <p className="subtitle">
                            {isLogin ? 'Sign in to access your dashboard' : 'Register to join the nomination system'}
                        </p>
                    </header>
                    <form className="form" onSubmit={handleAuth}>
                        {!isLogin && (
                            <div className="input-group">
                                <label className="label">Full Name</label>
                                <input type="text" className="input" placeholder="John Doe" value={authForm.name}
                                    onChange={(e) => setAuthForm({ ...authForm, name: e.target.value })} />
                            </div>
                        )}
                        <div className="input-group">
                            <label className="label">Email Address</label>
                            <input type="email" className="input" placeholder="you@example.com" value={authForm.email}
                                onChange={(e) => setAuthForm({ ...authForm, email: e.target.value })} required />
                        </div>
                        <div className="input-group">
                            <label className="label">Password</label>
                            <input type="password" className="input" placeholder="••••••••" value={authForm.password}
                                onChange={(e) => setAuthForm({ ...authForm, password: e.target.value })} required minLength={8} />
                            <span className="input-hint">Minimum 8 characters</span>
                        </div>
                        {message.text && <div className={`message ${message.type}`}>{message.text}</div>}
                        <button type="submit" className="button" disabled={loading}>
                            {loading ? 'Processing...' : (isLogin ? 'Sign In' : 'Create Account')}
                        </button>
                        <p className="toggle-auth">
                            {isLogin ? "Don't have an account? " : "Already have an account? "}
                            <button type="button" className="link-button" onClick={() => { setIsLogin(!isLogin); setMessage({ type: '', text: '' }); }}>
                                {isLogin ? 'Register' : 'Sign In'}
                            </button>
                        </p>
                    </form>
                    <div className="security-badge">
                        <span className="security-icon">🔐</span>
                        <span>Protected by bcrypt encryption & JWT authentication</span>
                    </div>
                </div>
            </div>
        );
    }

    return (
        <div className="app dashboard-view">
            <div className="ambient-glow ambient-glow-1"></div>
            <div className="ambient-glow ambient-glow-2"></div>
            <div className="dashboard-container">
                <header className="dashboard-header">
                    <div className="header-left">
                        <h1 className="dashboard-title">Nomination System</h1>
                        <span className="user-email">{user?.email}</span>
                    </div>
                    <button className="logout-button" onClick={handleLogout}>Logout</button>
                </header>
                <nav className="tabs">
                    <button className={`tab ${activeTab === 'addresses' ? 'active' : ''}`} onClick={() => setActiveTab('addresses')}>📍 Addresses</button>
                    <button className={`tab ${activeTab === 'nominate' ? 'active' : ''}`} onClick={() => setActiveTab('nominate')}>🤝 Nominate</button>
                    <button className={`tab ${activeTab === 'tracking' ? 'active' : ''}`} onClick={() => setActiveTab('tracking')}>📊 Track All</button>
                </nav>
                {message.text && <div className={`message ${message.type}`}>{message.text}</div>}
                <main className="tab-content">
                    {activeTab === 'addresses' && (
                        <div className="addresses-section">
                            <div className="section-header">
                                <h2 className="section-title">Your Addresses</h2>
                                <button className="history-toggle" onClick={() => { setShowHistory(!showHistory); if (!showHistory) fetchAddressHistory(); }}>
                                    {showHistory ? '📍 Show Addresses' : '📜 Show Change History'}
                                </button>
                            </div>
                            {!showHistory ? (
                                <>
                                    <form className="address-form" onSubmit={editingAddress ? handleUpdateAddress : handleAddAddress}>
                                        <div className="form-grid">
                                            <div className="input-group">
                                                <label className="label">Label</label>
                                                <input type="text" className="input" placeholder="Home, Office, etc." value={addressForm.label}
                                                    onChange={(e) => setAddressForm({ ...addressForm, label: e.target.value })} required />
                                            </div>
                                            <div className="input-group">
                                                <label className="label">Street</label>
                                                <input type="text" className="input" placeholder="123 Main St" value={addressForm.street}
                                                    onChange={(e) => setAddressForm({ ...addressForm, street: e.target.value })} required />
                                            </div>
                                            <div className="input-group">
                                                <label className="label">City</label>
                                                <input type="text" className="input" placeholder="New York" value={addressForm.city}
                                                    onChange={(e) => setAddressForm({ ...addressForm, city: e.target.value })} required />
                                            </div>
                                            <div className="input-group">
                                                <label className="label">State</label>
                                                <input type="text" className="input" placeholder="NY" value={addressForm.state}
                                                    onChange={(e) => setAddressForm({ ...addressForm, state: e.target.value })} />
                                            </div>
                                            <div className="input-group">
                                                <label className="label">Postal Code</label>
                                                <input type="text" className="input" placeholder="10001" value={addressForm.postal_code}
                                                    onChange={(e) => setAddressForm({ ...addressForm, postal_code: e.target.value })} />
                                            </div>
                                            <div className="input-group">
                                                <label className="label">Country</label>
                                                <input type="text" className="input" placeholder="USA" value={addressForm.country}
                                                    onChange={(e) => setAddressForm({ ...addressForm, country: e.target.value })} required />
                                            </div>
                                        </div>
                                        <div className="form-actions">
                                            <button type="submit" className="button add-button" disabled={loading}>
                                                {editingAddress ? '✓ Save Changes' : '+ Add Address'}
                                            </button>
                                            {editingAddress && <button type="button" className="button cancel-button" onClick={cancelEdit}>Cancel</button>}
                                        </div>
                                        {editingAddress && <p className="edit-notice">📝 Editing "{editingAddress.label}" - Changes will be tracked in history</p>}
                                    </form>
                                    <div className="addresses-list">
                                        {addresses.length === 0 ? (
                                            <p className="empty-state">No addresses yet. Add your first address above.</p>
                                        ) : (
                                            addresses.map(addr => (
                                                <div key={addr.id} className="address-card">
                                                    <div className="address-info">
                                                        <span className="address-label">{addr.label}</span>
                                                        <p className="address-text">
                                                            {addr.street}, {addr.city}{addr.state && `, ${addr.state}`}{addr.postal_code && ` ${addr.postal_code}`}<br />{addr.country}
                                                        </p>
                                                    </div>
                                                    <div className="address-actions">
                                                        <button className="edit-button" onClick={() => startEditAddress(addr)}>✏️</button>
                                                        <button className="delete-button" onClick={() => handleDeleteAddress(addr.id)}>×</button>
                                                    </div>
                                                </div>
                                            ))
                                        )}
                                    </div>
                                </>
                            ) : (
                                <div className="address-history">
                                    <h3 className="history-title">📜 Address Change History</h3>
                                    <p className="history-subtitle">All changes to your addresses are tracked here</p>
                                    {addressHistory.length === 0 ? (
                                        <p className="empty-state">No changes recorded yet.</p>
                                    ) : (
                                        <div className="history-list">
                                            {addressHistory.map(h => (
                                                <div key={h.id} className={`history-card ${h.action.toLowerCase()}`}>
                                                    <div className="history-header">
                                                        <span className={`action-badge ${h.action.toLowerCase()}`}>{h.action}</span>
                                                        <span className="history-date">{new Date(h.changed_at).toLocaleString()}</span>
                                                    </div>
                                                    {h.action === 'CREATED' && (
                                                        <div className="history-content">
                                                            <p><strong>New:</strong> {h.new_label} - {h.new_street}, {h.new_city}, {h.new_country}</p>
                                                        </div>
                                                    )}
                                                    {h.action === 'UPDATED' && (
                                                        <div className="history-content">
                                                            <p className="old-value"><strong>Old:</strong> {h.old_label} - {h.old_street}, {h.old_city}, {h.old_country}</p>
                                                            <p className="arrow">↓</p>
                                                            <p className="new-value"><strong>New:</strong> {h.new_label} - {h.new_street}, {h.new_city}, {h.new_country}</p>
                                                        </div>
                                                    )}
                                                    {h.action === 'DELETED' && (
                                                        <div className="history-content">
                                                            <p className="old-value"><strong>Deleted:</strong> {h.old_label} - {h.old_street}, {h.old_city}, {h.old_country}</p>
                                                        </div>
                                                    )}
                                                </div>
                                            ))}
                                        </div>
                                    )}
                                </div>
                            )}
                        </div>
                    )}
                    {activeTab === 'nominate' && (
                        <div className="nominate-section">
                            <h2 className="section-title">Nominate a User</h2>
                            <form className="nomination-form" onSubmit={handleNominate}>
                                <div className="input-group">
                                    <label className="label">Select User to Nominate</label>
                                    <select className="input select" value={nominationForm.nominee_id}
                                        onChange={(e) => setNominationForm({ ...nominationForm, nominee_id: e.target.value })} required>
                                        <option value="">Choose a user...</option>
                                        {users.map(u => <option key={u.id} value={u.id}>{u.name || u.email}</option>)}
                                    </select>
                                </div>
                                <div className="input-group">
                                    <label className="label">Reason for Nomination</label>
                                    <textarea className="textarea" placeholder="Why are you nominating this user?" value={nominationForm.reason}
                                        onChange={(e) => setNominationForm({ ...nominationForm, reason: e.target.value })} rows={3} />
                                </div>
                                <button type="submit" className="button" disabled={loading}>Submit Nomination</button>
                            </form>
                            <div className="nominations-grid">
                                <div className="nominations-column">
                                    <h3 className="column-title">✅ Nominations You Gave ({nominationsGiven.length})</h3>
                                    {nominationsGiven.length === 0 ? (
                                        <p className="empty-state">You haven't nominated anyone yet.</p>
                                    ) : (
                                        nominationsGiven.map(n => (
                                            <div key={n.id} className="nomination-card">
                                                <p className="nomination-user">→ {n.nominee_name || n.nominee_email}</p>
                                                {n.reason && <p className="nomination-reason">"{n.reason}"</p>}
                                                <span className="nomination-date">{new Date(n.created_at).toLocaleDateString()}</span>
                                            </div>
                                        ))
                                    )}
                                </div>
                                <div className="nominations-column">
                                    <h3 className="column-title">🎉 Nominations You Received ({nominationsReceived.length})</h3>
                                    {nominationsReceived.length === 0 ? (
                                        <p className="empty-state">No one has nominated you yet.</p>
                                    ) : (
                                        nominationsReceived.map(n => (
                                            <div key={n.id} className="nomination-card received">
                                                <p className="nomination-user">← {n.nominator_name || n.nominator_email}</p>
                                                {n.reason && <p className="nomination-reason">"{n.reason}"</p>}
                                                <span className="nomination-date">{new Date(n.created_at).toLocaleDateString()}</span>
                                            </div>
                                        ))
                                    )}
                                </div>
                            </div>
                        </div>
                    )}
                    {activeTab === 'tracking' && (
                        <div className="tracking-section">
                            <h2 className="section-title">📊 All Nominations Tracker</h2>
                            <p className="section-subtitle">Complete traceability of who nominated whom</p>
                            <div className="tracking-table-container">
                                <table className="tracking-table">
                                    <thead>
                                        <tr>
                                            <th>Nominator</th>
                                            <th>📍 Location</th>
                                            <th>→</th>
                                            <th>Nominee</th>
                                            <th>📍 Location</th>
                                            <th>Reason</th>
                                            <th>Date</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {allNominations.length === 0 ? (
                                            <tr><td colSpan={7} className="empty-state">No nominations yet.</td></tr>
                                        ) : (
                                            allNominations.map(n => (
                                                <tr key={n.id}>
                                                    <td><span className="user-badge nominator">{n.nominator_name || n.nominator_email}</span></td>
                                                    <td className="location">{n.nominator_city || <span className="no-address">No address</span>}</td>
                                                    <td className="arrow">→</td>
                                                    <td><span className="user-badge nominee">{n.nominee_name || n.nominee_email}</span></td>
                                                    <td className="location">{n.nominee_city || <span className="no-address">No address</span>}</td>
                                                    <td className="reason">{n.reason || '-'}</td>
                                                    <td className="date">{new Date(n.created_at).toLocaleDateString()}</td>
                                                </tr>
                                            ))
                                        )}
                                    </tbody>
                                </table>
                            </div>
                            <div className="stats-grid">
                                <div className="stat-card">
                                    <span className="stat-number">{allNominations.length}</span>
                                    <span className="stat-label">Total Nominations</span>
                                </div>
                                <div className="stat-card">
                                    <span className="stat-number">{users.length + 1}</span>
                                    <span className="stat-label">Total Users</span>
                                </div>
                                <div className="stat-card">
                                    <span className="stat-number">{addresses.length}</span>
                                    <span className="stat-label">Your Addresses</span>
                                </div>
                            </div>
                        </div>
                    )}
                </main>
                <footer className="dashboard-footer">
                    <div className="security-features">
                        <span>🔐 Bcrypt Hashing</span>
                        <span>🎫 JWT Tokens</span>
                        <span>🛡️ SQL Injection Protected</span>
                        <span>✓ Input Validated</span>
                    </div>
                </footer>
            </div>
        </div>
    );
}

export default App;
