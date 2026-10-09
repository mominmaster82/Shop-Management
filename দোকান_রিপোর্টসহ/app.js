const ACCOUNT_STORAGE_KEY = 'erp_single_user_auth';
const AUTH_HASH_ITERATIONS = 120000;
const OFFLINE_DB_NAME = 'shop-management-offline';
const OFFLINE_DB_VERSION = 1;
let offlineDatabasePromise = null;
var currentUsername = null;
var currentUserRole = null;
var products = [];
var productCatalog = [];
var contacts = [];
var purchaseHistory = [];
var salesHistory = [];
var currentCart = [];
var selectedProductForSale = null;
let salesSuggestionIndex = -1;
var selectedProductForReturn = null;
var contactLedgerMode = 'Customer';
var storeConfig = { companyName: 'মেসার্স বিজনেস স্টোর', subtitle: 'ক্যাশ মেমো', address: '', logoData: '' };
var dueTransactions = [];
var productReturns = [];
var authBusy = false;
let purchaseSuggestionIndex = -1;

function appId() {
    return globalThis.crypto?.randomUUID
        ? crypto.randomUUID()
        : `${Date.now()}-${Math.random().toString(36).slice(2)}`;
}

function escapeHTML(value) {
    return String(value ?? '').replace(/[&<>"']/g, character => ({
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;'
    })[character]);
}

function elementValue(id) {
    return document.getElementById(id)?.value.trim() ?? '';
}

function amountValue(id) {
    const value = Number(document.getElementById(id)?.value);
    return Number.isFinite(value) ? value : NaN;
}

function setValue(id, value) {
    const element = document.getElementById(id);
    if (element) element.value = value ?? '';
}

function setText(id, value) {
    const element = document.getElementById(id);
    if (element) element.textContent = value ?? '';
}

function showAppError(message) {
    const error = document.getElementById('login-error');
    if (error) {
        error.textContent = message;
        error.style.display = 'block';
    } else {
        alert(message);
    }
}

function clearAppError() {
    const error = document.getElementById('login-error');
    if (error) {
        error.textContent = '';
        error.style.display = 'none';
    }
}

function setAuthBusy(busy) {
    authBusy = busy;
    document.querySelector('.btn-signin').disabled = busy;
    document.querySelector('.btn-signup').disabled = busy;
}

function showSaveError(error, action) {
    console.error(`${action} failed:`, error);
    alert(`${action}: ${error.message || error}`);
}

function formatMoney(value) {
    return (Number(value) || 0).toLocaleString('en-US', { maximumFractionDigits: 2 });
}

function requireValidAmount(value, label, { allowZero = false } = {}) {
    if (!Number.isFinite(value) || (allowZero ? value < 0 : value <= 0)) {
        throw new Error(`${label} ${allowZero ? 'শূন্য বা তার বেশি' : 'শূন্যের বেশি'} হতে হবে।`);
    }
    return value;
}

function todayISO() {
    const date = new Date();
    return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}-${String(date.getDate()).padStart(2, '0')}`;
}

function randomSalt() {
    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    return btoa(String.fromCharCode(...bytes));
}

async function hashPassword(password, salt = randomSalt()) {
    if (!crypto?.subtle) {
        throw new Error('নিরাপদ পাসওয়ার্ড সংরক্ষণের জন্য HTTPS বা localhost ব্যবহার করুন।');
    }
    const key = await crypto.subtle.importKey(
        'raw',
        new TextEncoder().encode(password),
        'PBKDF2',
        false,
        ['deriveBits']
    );
    const result = await crypto.subtle.deriveBits({
        name: 'PBKDF2',
        salt: Uint8Array.from(atob(salt), character => character.charCodeAt(0)),
        iterations: AUTH_HASH_ITERATIONS,
        hash: 'SHA-256'
    }, key, 256);
    return { salt, hash: btoa(String.fromCharCode(...new Uint8Array(result))) };
}

async function passwordMatches(password, stored) {
    if (!stored?.salt || !stored?.hash) return false;
    const candidate = await hashPassword(password, stored.salt);
    return candidate.hash === stored.hash;
}

function readLegacyAdminPassword() {
    const rawUsers = localStorage.getItem('erp_system_users');
    if (!rawUsers) return null;
    const users = JSON.parse(rawUsers);
    if (!Array.isArray(users)) throw new Error('পুরনো ইউজার ডেটা পড়া যাচ্ছে না।');
    const admin = users.find(user => user?.role === 'ADMIN' && typeof user.password === 'string');
    return admin?.password ?? null;
}

function validateLoginInputs() {
    const username = elementValue('username-input');
    const password = document.getElementById('password-input').value;
    if (!username || !password) throw new Error('ইউজারনেম ও পাসওয়ার্ড দিন।');
    return { username, password };
}

async function attemptLogin() {
    if (authBusy) return;
    setAuthBusy(true);
    clearAppError();
    try {
        const { username, password } = validateLoginInputs();
        const account = JSON.parse(localStorage.getItem(ACCOUNT_STORAGE_KEY) || 'null');
        if (!account) {
            throw new Error('প্রথমে “প্রথম সেটআপ / লগইন রিসেট” ব্যবহার করে একক ইউজার সেটআপ করুন।');
        }
        if (username !== account.username || !await passwordMatches(password, account.password)) {
            throw new Error('ইউজারনেম বা পাসওয়ার্ড সঠিক নয়। ভুলে গেলে recovery/admin password দিয়ে রিসেট করুন।');
        }
        currentUsername = account.username;
        currentUserRole = 'ADMIN';
        await initAppSession();
    } catch (error) {
        showAppError(error.message || 'লগইন করা যায়নি।');
    } finally {
        setAuthBusy(false);
    }
}

async function attemptSignup() {
    if (authBusy) return;
    setAuthBusy(true);
    clearAppError();
    try {
        const { username, password } = validateLoginInputs();
        const recoveryPassword = document.getElementById('recovery-password-input').value;
        if (password.length < 8) throw new Error('নতুন পাসওয়ার্ড কমপক্ষে ৮ অক্ষরের হতে হবে।');
        const account = JSON.parse(localStorage.getItem(ACCOUNT_STORAGE_KEY) || 'null');
        const legacyAdminPassword = account ? null : readLegacyAdminPassword();
        const isLegacyAdminRecovery = !account && legacyAdminPassword === recoveryPassword;
        if (recoveryPassword.length < 8 && !isLegacyAdminRecovery) {
            throw new Error('Recovery/admin password কমপক্ষে ৮ অক্ষরের হতে হবে।');
        }
        if (recoveryPassword === password) throw new Error('নিরাপত্তার জন্য recovery password-টি login password থেকে আলাদা রাখুন।');
        if (!recoveryPassword) throw new Error('Recovery/admin password দিন।');
        if (account && !await passwordMatches(recoveryPassword, account.recovery)) {
            throw new Error('Recovery/admin password সঠিক নয়।');
        }

        let recovery = account?.recovery;
        if (!account) {
            if (legacyAdminPassword && recoveryPassword !== legacyAdminPassword) {
                throw new Error('পুরনো অ্যাডমিন পাসওয়ার্ড দিন; সেটিই প্রথম recovery password হিসেবে রাখা হবে।');
            }
            recovery = await hashPassword(recoveryPassword);
        }

        const passwordHash = await hashPassword(password);
        const nextAccount = {
            username,
            password: passwordHash,
            recovery,
            updatedAt: new Date().toISOString()
        };
        localStorage.setItem(ACCOUNT_STORAGE_KEY, JSON.stringify(nextAccount));
        localStorage.removeItem('erp_system_users');
        document.getElementById('password-input').value = '';
        document.getElementById('recovery-password-input').value = '';
        document.getElementById('password-input').setAttribute('autocomplete', 'current-password');
        alert(account
            ? 'লগইন ইউজারনেম ও পাসওয়ার্ড রিসেট হয়েছে।'
            : 'একক ইউজার সেটআপ সম্পন্ন। এখন নতুন ইউজারনেম ও পাসওয়ার্ড দিয়ে লগইন করুন।');
    } catch (error) {
        showAppError(error.message || 'সেটআপ বা রিসেট সম্পন্ন হয়নি।');
    } finally {
        setAuthBusy(false);
    }
}

function buildAllData() {
    return {
        shopId: SHOP_ID,
        products,
        productCatalog,
        contacts,
        purchaseHistory,
        salesHistory,
        dueTransactions,
        productReturns,
        storeConfig,
        meta: {
            updatedAt: localDataUpdatedAt || Date.now(),
            appVersion: 'single-user-v2'
        }
    };
}

function loadLocalDataObject(data) {
    if (!data || typeof data !== 'object' || Array.isArray(data)) {
        throw new Error('সংরক্ষিত ডেটার ফরম্যাট সঠিক নয়।');
    }
    for (const key of ['products', 'productCatalog', 'contacts', 'purchaseHistory', 'salesHistory']) {
        if (data[key] !== undefined && !Array.isArray(data[key])) {
            throw new Error(`সংরক্ষিত ${key} ডেটার ফরম্যাট সঠিক নয়।`);
        }
        if (Array.isArray(data[key]) && data[key].some(record => !record || typeof record !== 'object' || Array.isArray(record))) {
            throw new Error(`সংরক্ষিত ${key} ডেটায় অবৈধ রেকর্ড আছে।`);
        }
    }
    products = (data.products || []).map(product => ({ ...product, id: product.id || appId() }));
    productCatalog = (data.productCatalog || products.map(product => ({
        id: product.catalogId || appId(),
        name: product.name,
        unit: product.unit || 'পিস'
    }))).map(item => ({ ...item, id: item.id || appId() }));
    contacts = (data.contacts || []).map(contact => ({ ...contact, id: contact.id || appId() }));
    purchaseHistory = data.purchaseHistory || [];
    salesHistory = data.salesHistory || [];
    dueTransactions = Array.isArray(data.dueTransactions) ? data.dueTransactions : [];
    productReturns = Array.isArray(data.productReturns) ? data.productReturns : [];
    if (data.storeConfig && typeof data.storeConfig === 'object') {
        storeConfig = { ...storeConfig, ...data.storeConfig };
    }
    localDataUpdatedAt = Number(data.meta?.updatedAt) || Date.now();
}

function openOfflineDatabase() {
    if (!('indexedDB' in window)) return Promise.resolve(null);
    if (!offlineDatabasePromise) {
        offlineDatabasePromise = new Promise(resolve => {
            const request = indexedDB.open(OFFLINE_DB_NAME, OFFLINE_DB_VERSION);
            request.onupgradeneeded = () => {
                if (!request.result.objectStoreNames.contains('shopData')) {
                    request.result.createObjectStore('shopData', { keyPath: 'shopId' });
                }
            };
            request.onsuccess = () => {
                const database = request.result;
                database.onversionchange = () => database.close();
                resolve(database);
            };
            request.onerror = () => {
                offlineDatabasePromise = null;
                resolve(null);
            };
        });
    }
    return offlineDatabasePromise;
}

async function readOfflineData() {
    const database = await openOfflineDatabase();
    if (!database) {
        const raw = localStorage.getItem(LOCAL_DATA_KEY);
        return raw ? JSON.parse(raw) : null;
    }
    return new Promise((resolve, reject) => {
        const transaction = database.transaction('shopData', 'readonly');
        const request = transaction.objectStore('shopData').get(SHOP_ID);
        request.onsuccess = () => resolve(request.result || null);
        request.onerror = () => reject(request.error || new Error('সংরক্ষিত ডেটা পড়া যায়নি।'));
    });
}

async function writeOfflineData(data) {
    const database = await openOfflineDatabase();
    if (!database) {
        localStorage.setItem(LOCAL_DATA_KEY, JSON.stringify(data));
        return data;
    }
    return new Promise((resolve, reject) => {
        const transaction = database.transaction('shopData', 'readwrite');
        transaction.objectStore('shopData').put(data);
        transaction.oncomplete = () => resolve(data);
        transaction.onerror = () => reject(transaction.error || new Error('ডেটা সংরক্ষণ করা যায়নি।'));
        transaction.onabort = () => reject(transaction.error || new Error('ডেটা সংরক্ষণ বাতিল হয়েছে।'));
    });
}

async function persistLocalData(markChanged = true) {
    if (markChanged) localDataUpdatedAt = Date.now();
    const data = buildAllData();
    await writeOfflineData(data);
    localStorage.setItem(`erp_data_updated_${SHOP_ID}`, String(localDataUpdatedAt));
    return data;
}

function saveDataToServer() {
    return persistLocalData(true);
}

async function loadDataFromServer() {
    const data = await readOfflineData();
    if (data) {
        loadLocalDataObject(data);
    } else {
        const legacyRaw = localStorage.getItem(LOCAL_DATA_KEY);
        loadLocalDataObject(legacyRaw ? JSON.parse(legacyRaw) : {});
        await persistLocalData(false);
        if (await openOfflineDatabase()) localStorage.removeItem(LOCAL_DATA_KEY);
    }
    applySettingsToUI();
    refreshAllViews();
}

function voucherNumberExists(voucherNumber) {
    return purchaseHistory.some(record => record.vNo === voucherNumber) ||
        salesHistory.some(record => record.vCode === voucherNumber);
}

function createUniqueVoucherNumber(prefix) {
    let counter = Number(localStorage.getItem(`erp_voucher_counter_${SHOP_ID}`)) || 0;
    let voucherNumber;
    do {
        counter += 1;
        voucherNumber = `${prefix}-${new Date().getFullYear()}${String(counter).padStart(6, '0')}`;
    } while (voucherNumberExists(voucherNumber));
    localStorage.setItem(`erp_voucher_counter_${SHOP_ID}`, String(counter));
    return voucherNumber;
}

function renderProductCatalog() {
    const body = document.getElementById('product-catalog-body');
    if (!body) return;
    const filterText = (document.getElementById('catalog-product-filter')?.value || '').trim().toLowerCase();
    const rows = productCatalog.filter(item => !filterText || item.name.toLowerCase().includes(filterText));
    body.innerHTML = rows.map((item, index) => `<tr>
        <td>${escapeHTML(item.name)}</td>
        <td>${escapeHTML(item.unit || 'পিস')}</td>
        <td><button class="btn btn-warning btn-sm" onclick="editCatalogEntry(${index})">এডিট</button>
        <button class="btn btn-danger btn-sm" onclick="deleteCatalogEntry(${index})">মুছুন</button></td>
    </tr>`).join('') || '<tr><td colspan="3">কোনো পণ্য যোগ করা হয়নি।</td></tr>';
}

function renderDashboardSummaryCards() {
    const container = document.getElementById('dashboard-summary');
    if (!container) return;
    const totalProducts = products.length;
    const totalStockQty = products.reduce((sum, product) => sum + Number(product.qty || 0), 0);
    const lowStockCount = products.filter(product => Number(product.qty || 0) <= 5).length;
    const totalBalance = contacts.reduce((sum, contact) => sum + Number(contactBalance(contact) || 0), 0);
    const todaySales = salesHistory.filter(record => record.date === todayISO()).reduce((sum, record) => sum + Number(record.total || 0), 0);
    const todaySalesCount = salesHistory.filter(record => record.date === todayISO()).length;
    const todayPurchase = purchaseHistory.filter(record => record.date === todayISO()).reduce((sum, record) => sum + Number(record.total || 0), 0);
    container.innerHTML = `
        <div class="dashboard-card">
            <span class="dashboard-label">মোট পণ্য</span>
            <strong>${formatMoney(totalProducts)}</strong>
        </div>
        <div class="dashboard-card">
            <span class="dashboard-label">মোট স্টক</span>
            <strong>${formatMoney(totalStockQty)}</strong>
        </div>
        <div class="dashboard-card danger-card">
            <span class="dashboard-label">Low Stock</span>
            <strong>${formatMoney(lowStockCount)}</strong>
        </div>
        <div class="dashboard-card">
            <span class="dashboard-label">আজকে বিক্রয়</span>
            <strong>৳${formatMoney(todaySales)}</strong>
        </div>
        <div class="dashboard-card">
            <span class="dashboard-label">আজকে ক্রয়</span>
            <strong>৳${formatMoney(todayPurchase)}</strong>
        </div>
        <div class="dashboard-card">
            <span class="dashboard-label">সামগ্রিক বকেয়া</span>
            <strong>৳${formatMoney(totalBalance)}</strong>
        </div>
        <div class="dashboard-card">
            <span class="dashboard-label">আজ বিক্রয়ের ভাউচার</span>
            <strong>${formatMoney(todaySalesCount)}</strong>
        </div>
    `;
}

function renderSalesChart() {
    const canvas = document.getElementById('sales-chart');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    const days = 7;
    const labels = [];
    const values = [];
    for (let offset = days - 1; offset >= 0; offset -= 1) {
        const date = new Date();
        date.setDate(date.getDate() - offset);
        const iso = date.toISOString().slice(0, 10);
        labels.push(date.toLocaleDateString('bn-BD', { day: 'numeric', month: 'short' }));
        values.push(salesHistory.filter(record => record.date === iso).reduce((sum, record) => sum + Number(record.total || 0), 0));
    }
    const width = canvas.width = 760;
    const height = canvas.height = 220;
    const padding = { top: 25, right: 20, bottom: 30, left: 50 };
    const chartWidth = width - padding.left - padding.right;
    const chartHeight = height - padding.top - padding.bottom;
    const maxValue = Math.max(...values, 1);
    ctx.clearRect(0, 0, width, height);
    ctx.strokeStyle = '#dfeaf5';
    ctx.lineWidth = 1;
    for (let step = 0; step <= 4; step += 1) {
        const y = padding.top + (chartHeight / 4) * step;
        ctx.beginPath();
        ctx.moveTo(padding.left, y);
        ctx.lineTo(width - padding.right, y);
        ctx.stroke();
    }
    ctx.strokeStyle = '#6b7a90';
    ctx.beginPath();
    ctx.moveTo(padding.left, padding.top);
    ctx.lineTo(padding.left, height - padding.bottom);
    ctx.lineTo(width - padding.right, height - padding.bottom);
    ctx.stroke();
    ctx.fillStyle = '#4a5d7a';
    ctx.font = '11px sans-serif';
    labels.forEach((label, index) => {
        const x = padding.left + (chartWidth / labels.length) * index + (chartWidth / labels.length) / 2;
        ctx.fillText(label, x - 18, height - 10);
    });
    ctx.fillStyle = '#2d6cdf';
    const barWidth = chartWidth / labels.length * 0.6;
    values.forEach((value, index) => {
        const x = padding.left + (chartWidth / labels.length) * index + (chartWidth / labels.length - barWidth) / 2;
        const barHeight = (value / maxValue) * chartHeight;
        const y = height - padding.bottom - barHeight;
        ctx.fillRect(x, y, barWidth, barHeight);
    });
    ctx.fillStyle = '#2c3e50';
    ctx.font = '12px sans-serif';
    ctx.fillText('৭ দিনের বিক্রয়', padding.left, 16);
}

function renderBusinessReportData() {
    const summary = document.getElementById('party-summary-table');
    if (!summary) return;
    const customers = contacts.filter(contact => contact.type === 'Customer');
    const suppliers = contacts.filter(contact => contact.type === 'Supplier');
    const customerRows = customers.map(contact => `
        <tr>
            <td>${escapeHTML(contact.name)}</td>
            <td>${escapeHTML(contact.category || 'RETAIL')}</td>
            <td>${formatMoney(contactBalance(contact))}</td>
        </tr>
    `).join('') || '<tr><td colspan="3">কোনো কাস্টমার নেই।</td></tr>';
    const supplierRows = suppliers.map(contact => `
        <tr>
            <td>${escapeHTML(contact.name)}</td>
            <td>${formatMoney(contactBalance(contact))}</td>
        </tr>
    `).join('') || '<tr><td colspan="2">কোনো সাপ্লায়ার নেই।</td></tr>';
    summary.innerHTML = `
        <div class="report-grid">
            <div class="report-panel">
                <h4>কাস্টমার সারাংশ</h4>
                <table class="compact-table">
                    <thead><tr><th>নাম</th><th>ক্যাটাগরি</th><th>বকেয়া</th></tr></thead>
                    <tbody>${customerRows}</tbody>
                </table>
            </div>
            <div class="report-panel">
                <h4>সরবরাহকারী সারাংশ</h4>
                <table class="compact-table">
                    <thead><tr><th>নাম</th><th>দেনা/পাওনা</th></tr></thead>
                    <tbody>${supplierRows}</tbody>
                </table>
            </div>
        </div>
    `;
    const dailyBlock = document.getElementById('daily-summary-body');
    if (!dailyBlock) return;
    const today = todayISO();
    const todaySales = salesHistory.filter(record => record.date === today);
    const todayPurchase = purchaseHistory.filter(record => record.date === today);
    const lowStockItems = products.filter(product => Number(product.qty || 0) <= 5).slice(0, 6);
    const salesTotal = todaySales.reduce((sum, record) => sum + Number(record.total || 0), 0);
    const purchaseTotal = todayPurchase.reduce((sum, record) => sum + Number(record.total || 0), 0);
    dailyBlock.innerHTML = `
        <div class="report-stat-grid">
            <div class="mini-stat"><span>আজ বিক্রয়</span><strong>৳${formatMoney(salesTotal)}</strong></div>
            <div class="mini-stat"><span>আজ ক্রয়</span><strong>৳${formatMoney(purchaseTotal)}</strong></div>
            <div class="mini-stat"><span>বিক্রয় ভাউচার</span><strong>${formatMoney(todaySales.length)}</strong></div>
            <div class="mini-stat"><span>ক্রয় ভাউচার</span><strong>${formatMoney(todayPurchase.length)}</strong></div>
            <div class="mini-stat"><span>Low Stock</span><strong>${formatMoney(lowStockItems.length)}</strong></div>
            <div class="mini-stat"><span>ভাউচার ও বকেয়া</span><strong>৳${formatMoney(contacts.reduce((sum, contact) => sum + Number(contactBalance(contact) || 0), 0))}</strong></div>
        </div>
        <div class="daily-list-box">
            <h4>আজকের low stock পণ্য</h4>
            ${lowStockItems.length ? lowStockItems.map(product => `<div class="stock-alert-item">${escapeHTML(product.name)} — ${formatMoney(product.qty)} ${escapeHTML(product.unit || 'পিস')}</div>`).join('') : '<div class="stock-alert-item muted">কোনো low stock পণ্য নেই।</div>'}
        </div>
    `;
}

function printDailySummary() {
    document.body.classList.add('print-daily-report');
    window.addEventListener('afterprint', () => document.body.classList.remove('print-daily-report'), { once: true });
    window.print();
}

function renderAllStockTable() {
    const body = document.getElementById('all-stock-body');
    if (!body) return;
    body.innerHTML = products.map(product => {
        const isLowStock = Number(product.qty) <= 5;
        return `<tr class="${isLowStock ? 'low-stock-row' : ''}">
        <td>${escapeHTML(product.name)}</td><td>${escapeHTML(product.unit || 'পিস')}</td>
        <td>${formatMoney(product.cost)}</td><td>${formatMoney(product.price)}</td>
        <td>${formatMoney(product.wsPrice)}</td><td>${formatMoney(product.qty)}</td>
        <td><button class="btn btn-warning btn-sm" onclick="openProductEdit('${escapeHTML(product.id)}')">এডিট</button>
        <button class="btn btn-danger btn-sm" onclick="deleteStockProduct('${escapeHTML(product.id)}')">মুছুন</button></td>
    </tr>`;
    }).join('') || '<tr><td colspan="7">স্টকে এখনো কোনো পণ্য নেই।</td></tr>';
}

function renderContacts() {
    const customers = contacts.filter(contact => contact.type === 'Customer');
    const suppliers = contacts.filter(contact => contact.type === 'Supplier');
    const customerBody = document.getElementById('customer-list-body');
    const supplierBody = document.getElementById('supplier-list-body');
    if (customerBody) customerBody.innerHTML = customers.map(contact => `<tr>
        <td><span class="party-link" onclick="openContactProfile('${escapeHTML(contact.id)}')">${escapeHTML(contact.name)}</span></td>
        <td>${escapeHTML(contact.category || 'RETAIL')}</td><td>${escapeHTML(contact.phone || '')}</td>
        <td>${formatMoney(contactBalance(contact))}</td><td>${contactActions(contact)}</td>
    </tr>`).join('') || '<tr><td colspan="5">কোনো কাস্টমার নেই।</td></tr>';
    if (supplierBody) supplierBody.innerHTML = suppliers.map(contact => `<tr>
        <td><span class="party-link" onclick="openContactProfile('${escapeHTML(contact.id)}')">${escapeHTML(contact.name)}</span></td>
        <td>${escapeHTML(contact.phone || '')}</td><td>${formatMoney(contactBalance(contact))}</td>
        <td>${contactActions(contact)}</td>
    </tr>`).join('') || '<tr><td colspan="4">কোনো সাপ্লায়ার নেই।</td></tr>';
}

function contactActions(contact) {
    return `<button class="btn btn-primary btn-sm" onclick="openContactEdit('${escapeHTML(contact.id)}')">এডিট</button>
        <button class="btn btn-secondary btn-sm" onclick="openContactProfile('${escapeHTML(contact.id)}')">খাতা</button>`;
}

function setOptions(id, options, placeholder, selectedValue = '') {
    const select = document.getElementById(id);
    if (!select) return;
    select.innerHTML = `<option value="">${escapeHTML(placeholder)}</option>` + options.map(option =>
        `<option value="${escapeHTML(option.value)}">${escapeHTML(option.label)}</option>`
    ).join('');
    if (selectedValue && [...select.options].some(option => option.value === selectedValue)) select.value = selectedValue;
}

function applyProductFilterForSales(searchText = '') {
    const term = String(searchText || '').trim().toLowerCase();
    const options = products.filter(product => Number(product.qty) > 0 && (!term || product.name.toLowerCase().includes(term)))
        .map(product => ({
            value: product.id,
            label: `${product.name} — স্টক: ${Number(product.qty).toLocaleString('en-US', { maximumFractionDigits: 2 })} ${product.unit || 'পিস'}`
        }));
    setOptions('s-item-search', options, '-- পণ্য নির্বাচন করুন --');
    salesSuggestionIndex = -1;
    renderSalesProductSuggestions(options);
    if (selectedProductForSale) {
        const currentValue = selectedProductForSale.id;
        const match = options.some(option => option.value === currentValue);
        if (!match) selectedProductForSale = null;
    }
}

function renderSalesProductSuggestions(options) {
    const input = document.getElementById('sales-product-filter');
    const results = document.getElementById('sales-product-results');
    if (!input || !results) return;
    const shouldShow = document.activeElement === input && Boolean(input.value.trim());
    results.innerHTML = options.length
        ? options.slice(0, 8).map((option, index) => `<button type="button" id="sales-product-option-${index}" class="product-suggestion" role="option" aria-selected="false" data-product-id="${escapeHTML(option.value)}">${escapeHTML(option.label)}</button>`).join('')
        : '<div>কোনো পণ্য পাওয়া যায়নি।</div>';
    results.style.display = shouldShow ? 'block' : 'none';
    input.setAttribute('aria-expanded', String(shouldShow));
    results.onclick = event => {
        const suggestion = event.target.closest('[data-product-id]');
        if (suggestion) selectSalesProduct(suggestion.dataset.productId);
    };
}

function selectSalesProduct(productId) {
    const product = getProduct(productId);
    if (!product) return;
    setValue('sales-product-filter', product.name);
    applyProductFilterForSales(product.name);
    setValue('s-item-search', product.id);
    handleSalesProductSelect();
    hideSalesProductSuggestions();
}

function handleSalesProductFilterKeydown(event) {
    const results = document.getElementById('sales-product-results');
    const suggestions = [...(results?.querySelectorAll('[data-product-id]') || [])];
    if (!suggestions.length || results.style.display === 'none') {
        if (event.key === 'Escape') hideSalesProductSuggestions();
        return;
    }
    if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
        event.preventDefault();
        const direction = event.key === 'ArrowDown' ? 1 : -1;
        salesSuggestionIndex = salesSuggestionIndex < 0
            ? (direction === 1 ? 0 : suggestions.length - 1)
            : (salesSuggestionIndex + direction + suggestions.length) % suggestions.length;
        suggestions.forEach((suggestion, index) => suggestion.setAttribute('aria-selected', String(index === salesSuggestionIndex)));
        document.getElementById('sales-product-filter').setAttribute('aria-activedescendant', suggestions[salesSuggestionIndex].id);
        suggestions[salesSuggestionIndex].scrollIntoView({ block: 'nearest' });
    } else if (event.key === 'Enter' && salesSuggestionIndex >= 0) {
        event.preventDefault();
        selectSalesProduct(suggestions[salesSuggestionIndex].dataset.productId);
    } else if (event.key === 'Escape') {
        hideSalesProductSuggestions();
    }
}

function hideSalesProductSuggestions() {
    const input = document.getElementById('sales-product-filter');
    const results = document.getElementById('sales-product-results');
    if (results) results.style.display = 'none';
    if (input) {
        input.setAttribute('aria-expanded', 'false');
        input.removeAttribute('aria-activedescendant');
    }
    salesSuggestionIndex = -1;
}

function applyProductFilterForPurchase(searchText = '') {
    const term = String(searchText || '').trim().toLowerCase();
    const selectedValue = elementValue('p-name');
    const options = productCatalog.filter(item => !term || item.name.toLowerCase().includes(term))
        .map(item => ({ value: item.id, label: item.name }));
    setOptions('p-name', options, '-- পণ্য নির্বাচন করুন --', selectedValue);
    purchaseSuggestionIndex = -1;
    renderPurchaseProductSuggestions(options);
    if (selectedValue && !options.some(option => option.value === selectedValue)) {
        handlePurchaseProductSelect();
    }
}

function renderPurchaseProductSuggestions(options) {
    const input = document.getElementById('purchase-product-filter');
    const results = document.getElementById('purchase-product-results');
    if (!input || !results) return;
    const shouldShow = document.activeElement === input && Boolean(input.value.trim());
    results.innerHTML = options.length
        ? options.slice(0, 8).map((option, index) => `<button type="button" id="purchase-product-option-${index}" class="product-suggestion" role="option" aria-selected="false" data-product-id="${escapeHTML(option.value)}">${escapeHTML(option.label)}</button>`).join('')
        : '<div>কোনো পণ্য পাওয়া যায়নি।</div>';
    results.style.display = shouldShow ? 'block' : 'none';
    input.setAttribute('aria-expanded', String(shouldShow));
    results.onclick = event => {
        const suggestion = event.target.closest('[data-product-id]');
        if (suggestion) selectPurchaseProduct(suggestion.dataset.productId);
    };
}

function selectPurchaseProduct(productId) {
    const item = getCatalogItem(productId);
    if (!item) return;
    setValue('purchase-product-filter', item.name);
    applyProductFilterForPurchase(item.name);
    setValue('p-name', item.id);
    handlePurchaseProductSelect();
    hidePurchaseProductSuggestions();
}

function handlePurchaseProductFilterKeydown(event) {
    const results = document.getElementById('purchase-product-results');
    const suggestions = [...(results?.querySelectorAll('[data-product-id]') || [])];
    if (!suggestions.length || results.style.display === 'none') {
        if (event.key === 'Escape') hidePurchaseProductSuggestions();
        return;
    }
    if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
        event.preventDefault();
        const direction = event.key === 'ArrowDown' ? 1 : -1;
        purchaseSuggestionIndex = purchaseSuggestionIndex < 0
            ? (direction === 1 ? 0 : suggestions.length - 1)
            : (purchaseSuggestionIndex + direction + suggestions.length) % suggestions.length;
        suggestions.forEach((suggestion, index) => suggestion.setAttribute('aria-selected', String(index === purchaseSuggestionIndex)));
        document.getElementById('purchase-product-filter').setAttribute('aria-activedescendant', suggestions[purchaseSuggestionIndex].id);
        suggestions[purchaseSuggestionIndex].scrollIntoView({ block: 'nearest' });
    } else if (event.key === 'Enter' && purchaseSuggestionIndex >= 0) {
        event.preventDefault();
        selectPurchaseProduct(suggestions[purchaseSuggestionIndex].dataset.productId);
    } else if (event.key === 'Escape') {
        hidePurchaseProductSuggestions();
    }
}

function hidePurchaseProductSuggestions() {
    const input = document.getElementById('purchase-product-filter');
    const results = document.getElementById('purchase-product-results');
    if (results) results.style.display = 'none';
    if (input) {
        input.setAttribute('aria-expanded', 'false');
        input.removeAttribute('aria-activedescendant');
    }
    purchaseSuggestionIndex = -1;
}

function filterProductCatalogTable(searchText = '') {
    const term = String(searchText || '').trim().toLowerCase();
    const body = document.getElementById('product-catalog-body');
    if (!body) return;
    const rows = productCatalog.filter(item => !term || item.name.toLowerCase().includes(term));
    body.innerHTML = rows.map((item, index) => `<tr>
        <td>${escapeHTML(item.name)}</td>
        <td>${escapeHTML(item.unit || 'পিস')}</td>
        <td><button class="btn btn-warning btn-sm" onclick="editCatalogEntry(${index})">এডিট</button>
        <button class="btn btn-danger btn-sm" onclick="deleteCatalogEntry(${index})">মুছুন</button></td>
    </tr>`).join('') || '<tr><td colspan="3">কোনো ম্যাচিং পণ্য পাওয়া যায়নি।</td></tr>';
}

function refreshSelects() {
    applyProductFilterForPurchase(document.getElementById('purchase-product-filter')?.value || '');
    applyProductFilterForSales(document.getElementById('sales-product-filter')?.value || '');
    setOptions('p-supplier-select', contacts.filter(contact => contact.type === 'Supplier')
        .map(contact => ({ value: contact.id, label: contact.name })), 'নগদ সরবরাহকারী');
    setOptions('s-customer-select', contacts.filter(contact => contact.type === 'Customer')
        .map(contact => ({ value: contact.id, label: contact.name })), 'নগদ কাস্টমার', 'Walk-in');
    handleReturnTypeChange();
    updatePurchaseValidationSummary();
    updateSalesValidationSummary();
}

function updatePurchaseValidationSummary() {
    const container = document.getElementById('purchase-validation-summary');
    if (!container) return;
    const cost = Number(document.getElementById('p-cost')?.value || 0);
    const quantity = Number(document.getElementById('p-qty')?.value || 0);
    const total = Math.max(0, cost * quantity);
    const paid = Number(document.getElementById('p-paid')?.value || 0);
    const supplierId = elementValue('p-supplier-select');
    const isCashSupplier = !supplierId;
    const due = total - paid;
    container.innerHTML = `
        <strong>ভ্যালিডেশন সারাংশ:</strong>
        <span>মোট বিল: ৳${formatMoney(total)}</span> |
        <span>পরিশোধ: ৳${formatMoney(paid)}</span> |
        <span>বাকি: ৳${formatMoney(due)}</span>
        <span class="status-badge ${isCashSupplier ? (Math.abs(paid - total) < 0.009 ? 'ok' : 'warn') : 'info'}">${
            isCashSupplier ? (Math.abs(paid - total) < 0.009 ? 'সঠিক' : 'বিল পরিশোধ অ্যামাউন্ট লিখুন') : 'স্থায়ী সরবরাহকারী: পরিশোধ প্রয়োজন নেই'
        }</span>
    `;
    container.classList.toggle('summary-warn', isCashSupplier && Math.abs(paid - total) > 0.009);
    container.classList.toggle('summary-ok', isCashSupplier && Math.abs(paid - total) < 0.009);
}

function updateSalesValidationSummary() {
    const container = document.getElementById('sales-validation-summary');
    if (!container) return;
    const total = Number(document.getElementById('s-grand-total')?.value || 0);
    const paid = Number(document.getElementById('s-paid-amount')?.value || 0);
    const customerId = elementValue('s-customer-select');
    const isCashCustomer = !customerId || customerId === 'Walk-in';
    const due = total - paid;
    container.innerHTML = `
        <strong>ভ্যালিডেশন সারাংশ:</strong>
        <span>সর্বমোট বিল: ৳${formatMoney(total)}</span> |
        <span>পরিশোধ: ৳${formatMoney(paid)}</span> |
        <span>বাকি: ৳${formatMoney(due)}</span>
        <span class="status-badge ${isCashCustomer ? (Math.abs(paid - total) < 0.009 ? 'ok' : 'warn') : 'info'}">${
            isCashCustomer ? (Math.abs(paid - total) < 0.009 ? 'সঠিক' : 'বিল পরিশোধ অ্যামাউন্ট লিখুন') : 'স্থায়ী কাস্টমার: বকেয়া গ্রহণযোগ্য'
        }</span>
    `;
    container.classList.toggle('summary-warn', isCashCustomer && Math.abs(paid - total) > 0.009);
    container.classList.toggle('summary-ok', isCashCustomer && Math.abs(paid - total) < 0.009);
}

function escapeCsvValue(value) {
    const text = String(value ?? '');
    return `"${text.replace(/"/g, '""')}"`;
}

function calculatePurchaseTotal() {
    const cost = Number(document.getElementById('p-cost').value) || 0;
    const quantity = Number(document.getElementById('p-qty').value) || 0;
    setValue('p-total-bill', Math.max(0, cost * quantity).toFixed(2));
    updatePurchaseValidationSummary();
}

function calculateFinalSalesTotals() {
    const subTotal = Number(document.getElementById('s-sub-total').value) || 0;
    const shipping = Math.max(0, Number(document.getElementById('s-shipping').value) || 0);
    const taxPercent = Math.max(0, Number(document.getElementById('s-tax-percent').value) || 0);
    const discount = Math.max(0, Number(document.getElementById('s-discount').value) || 0);
    setValue('s-grand-total', Math.max(0, subTotal + shipping + subTotal * taxPercent / 100 - discount).toFixed(2));
    updateSalesValidationSummary();
}

function refreshSelects() {
    applyProductFilterForPurchase(document.getElementById('purchase-product-filter')?.value || '');
    applyProductFilterForSales(document.getElementById('sales-product-filter')?.value || '');
    setOptions('p-supplier-select', contacts.filter(contact => contact.type === 'Supplier')
        .map(contact => ({ value: contact.id, label: contact.name })), 'নগদ সরবরাহকারী');
    setOptions('s-customer-select', contacts.filter(contact => contact.type === 'Customer')
        .map(contact => ({ value: contact.id, label: contact.name })), 'নগদ কাস্টমার', 'Walk-in');
    handleReturnTypeChange();
    updatePurchaseValidationSummary();
    updateSalesValidationSummary();
}

function refreshAllViews() {
    refreshSelects();
    renderDashboardSummaryCards();
    renderBusinessReportData();
    renderProductCatalog();
    renderAllStockTable();
    renderContacts();
    renderCart();
    renderSalesChart();
}

function applySettingsToUI() {
    setValue('settings-comp-name', storeConfig.companyName);
    setValue('settings-comp-subtitle', storeConfig.subtitle);
    setValue('settings-comp-address', storeConfig.address);
    setText('prof-company-title', storeConfig.companyName);
    const preview = document.getElementById('settings-logo-preview');
    if (preview) {
        preview.src = storeConfig.logoData || '';
        preview.style.display = storeConfig.logoData ? 'block' : 'none';
    }
}

async function initAppSession() {
    try {
        await loadDataFromServer();
        document.getElementById('login-screen').style.display = 'none';
        document.getElementById('main-app').style.display = 'flex';
        setText('current-user-display', `👤 একক ইউজার: ${currentUsername}`);
        applyRolePermissions('ADMIN');
        clearAppError();
        setTimeout(() => window.dispatchEvent(new Event('resize')), 50);
    } catch (error) {
        console.error('App session could not start:', error);
        showAppError(`অ্যাপের ডেটা লোড হয়নি: ${error.message || error}`);
    }
}

function applyRolePermissions() {
    document.body.classList.remove('is-user');
    document.body.classList.add('is-admin');
    switchTab('sales-tab');
}

function renderAdminUsersTable() {
    const body = document.getElementById('admin-users-table-body');
    if (body) body.replaceChildren();
}

function switchTab(tabId) {
    const allowedTabs = new Set([
        'voucher-tab', 'report-tab', 'product-list-tab', 'stock-tab', 'purchase-tab', 'sales-tab',
        'return-tab', 'contacts-tab', 'settings-tab', 'export-data-tab', 'import-data-tab'
    ]);
    if (!allowedTabs.has(tabId)) return;
    document.querySelectorAll('.tab-content').forEach(tab => {
        tab.style.display = 'none';
        tab.classList.remove('active-tab');
    });
    document.querySelectorAll('.menu-btn').forEach(button => button.classList.remove('active'));
    const target = document.getElementById(tabId);
    if (!target) return;
    target.style.display = 'block';
    target.classList.add('active-tab');
    const buttonByTab = {
        'voucher-tab': 'btn-voucher-search',
        'report-tab': 'btn-report',
        'product-list-tab': 'btn-product-list',
        'stock-tab': 'btn-stock',
        'purchase-tab': 'btn-purchase',
        'sales-tab': 'btn-sales',
        'return-tab': 'btn-return',
        'settings-tab': 'btn-settings-profile',
        'export-data-tab': 'btn-export-data',
        'import-data-tab': 'btn-import-data'
    };
    document.getElementById(buttonByTab[tabId])?.classList.add('active');
    if (tabId === 'stock-tab') renderAllStockTable();
    if (tabId === 'product-list-tab') renderProductCatalog();
    if (tabId === 'contacts-tab') renderContacts();
    if (tabId === 'report-tab') {
        renderBusinessReportData();
        renderSalesChart();
    }
}

function logout() {
    currentUsername = null;
    currentUserRole = null;
    currentCart = [];
    document.getElementById('username-input').value = '';
    document.getElementById('password-input').value = '';
    document.getElementById('recovery-password-input').value = '';
    document.getElementById('main-app').style.display = 'none';
    document.getElementById('login-screen').style.display = 'flex';
    clearAppError();
}

async function editCatalogEntry(index) {
    const entry = productCatalog[index];
    if (!entry) return;
    const name = prompt('নতুন পণ্যের নাম লিখুন:', entry.name);
    if (name === null) return;
    const unit = prompt('পণ্যের ইউনিট লিখুন:', entry.unit || 'পিস');
    if (unit === null) return;
    const cleanName = name.trim();
    if (!cleanName || !unit.trim()) return alert('পণ্যের নাম ও ইউনিট দিতে হবে।');
    if (productCatalog.some((item, itemIndex) => itemIndex !== index && item.name.toLowerCase() === cleanName.toLowerCase())) {
        return alert('এই নামে পণ্য তালিকায় আগে থেকেই আছে।');
    }
    const oldName = entry.name;
    entry.name = cleanName;
    entry.unit = unit.trim();
    products.forEach(product => {
        if (product.catalogId === entry.id || product.name === oldName) {
            product.catalogId = entry.id;
            product.name = cleanName;
            product.unit = entry.unit;
        }
    });
    try { await saveDataToServer(); refreshAllViews(); } catch (error) { showSaveError(error, 'পণ্যের তালিকা সংরক্ষণ করা যায়নি'); }
}

async function deleteCatalogEntry(index) {
    const entry = productCatalog[index];
    if (!entry || !confirm(`“${entry.name}” পণ্য তালিকা থেকে মুছবেন?`)) return;
    const relatedProducts = products.filter(product => product.catalogId === entry.id || product.name === entry.name);
    if (relatedProducts.some(product => Number(product.qty) !== 0 ||
        purchaseHistory.some(record => record.items?.some(item => item.productId === product.id)) ||
        salesHistory.some(record => record.items?.some(item => item.productId === product.id)))) {
        return alert('স্টক বা লেনদেনের ইতিহাস থাকা পণ্য তালিকা থেকে মুছতে পারবেন না।');
    }
    productCatalog.splice(index, 1);
    products = products.filter(product => !relatedProducts.includes(product));
    try { await saveDataToServer(); refreshAllViews(); } catch (error) { showSaveError(error, 'পণ্য মুছা যায়নি'); }
}

async function saveProductCatalogEntry() {
    const name = elementValue('catalog-product-name');
    const unit = elementValue('catalog-product-unit') || 'পিস';
    if (!name) return alert('পণ্যের নাম লিখুন।');
    if (productCatalog.some(item => item.name.toLowerCase() === name.toLowerCase())) {
        return alert('এই পণ্যটি তালিকায় আগে থেকেই আছে।');
    }
    productCatalog.push({ id: appId(), name, unit });
    setValue('catalog-product-name', '');
    setValue('catalog-product-unit', '');
    try { await saveDataToServer(); refreshAllViews(); } catch (error) { showSaveError(error, 'পণ্য সংরক্ষণ করা যায়নি'); }
}

function getProduct(id) {
    return products.find(product => product.id === id);
}

function getCatalogItem(id) {
    return productCatalog.find(item => item.id === id);
}

function handlePurchaseProductSelect() {
    const item = getCatalogItem(elementValue('p-name'));
    setValue('p-unit', item?.unit || 'পিস');
    const product = products.find(record => record.catalogId === item?.id || record.name === item?.name);
    setValue('p-price', product?.price ?? '');
    setValue('p-ws-price', product?.wsPrice ?? '');
    setValue('p-cost', product?.cost ?? '');
    calculatePurchaseTotal();
}

async function savePurchase() {
    try {
        const catalog = getCatalogItem(elementValue('p-name'));
        if (!catalog) throw new Error('পণ্য নির্বাচন করুন।');
        const cost = requireValidAmount(amountValue('p-cost'), 'ক্রয়মূল্য');
        const quantity = requireValidAmount(amountValue('p-qty'), 'পরিমাণ');
        const total = cost * quantity;
        if (!Number.isFinite(total)) throw new Error('ক্রয়ের মোট বিল গ্রহণযোগ্য সীমার বাইরে।');
        const paid = requireValidAmount(amountValue('p-paid'), 'পরিশোধের টাকা', { allowZero: true });
        if (paid > total) throw new Error('পরিশোধের টাকা মোট বিলের বেশি হতে পারবে না।');
        const voucherNumber = elementValue('p-voucher-no') || createUniqueVoucherNumber('PUR');
        if (voucherNumberExists(voucherNumber)) throw new Error('এই ভাউচার নম্বরটি আগে থেকেই ব্যবহৃত হয়েছে।');
        const supplierId = elementValue('p-supplier-select');
        const isCashSupplier = !supplierId;
        if (isCashSupplier && Math.abs(paid - total) > 0.009) throw new Error('বিল পরিশোধ অ্যামাউন্ট লিখুন');
        const supplier = contacts.find(contact => contact.id === supplierId);
        const product = products.find(record => record.catalogId === catalog.id || record.name === catalog.name);
        const retailInput = document.getElementById('p-price').value;
        const wholesaleInput = document.getElementById('p-ws-price').value;
        const retailPrice = retailInput === '' ? Number(product?.price) || 0 : requireValidAmount(Number(retailInput), 'খুচরা বিক্রয়মূল্য', { allowZero: true });
        const wholesalePrice = wholesaleInput === '' ? Number(product?.wsPrice) || 0 : requireValidAmount(Number(wholesaleInput), 'পাইকারী বিক্রয়মূল্য', { allowZero: true });
        if (product) {
            const oldQty = Number(product.qty) || 0;
            product.cost = oldQty > 0 ? ((oldQty * Number(product.cost || 0)) + total) / (oldQty + quantity) : cost;
            product.qty = oldQty + quantity;
            product.price = retailPrice;
            product.wsPrice = wholesalePrice;
        } else {
            products.push({
                id: appId(), catalogId: catalog.id, name: catalog.name, unit: catalog.unit || 'পিস',
                cost, price: retailPrice, wsPrice: wholesalePrice,
                qty: quantity
            });
        }
        const record = {
            vNo: voucherNumber,
            date: todayISO(), supplierId: supplier?.id || null, supplier: supplier?.name || 'নগদ সরবরাহকারী',
            items: [{ productId: product?.id || products[products.length - 1].id, name: catalog.name, unit: catalog.unit || 'পিস', cost, price: cost, qty: quantity, total }],
            total, paid, due: total - paid
        };
        purchaseHistory.push(record);
        await saveDataToServer();
        setValue('p-voucher-no', '');
        setValue('p-qty', '');
        setValue('p-paid', '0');
        calculatePurchaseTotal();
        refreshAllViews();
        alert('পণ্য ক্রয় সংরক্ষণ হয়েছে।');
    } catch (error) {
        alert(error.message || 'পণ্য ক্রয় সংরক্ষণ করা যায়নি।');
    }
}

function handleCustomerSelect() {
    const customer = contacts.find(contact => contact.id === elementValue('s-customer-select'));
    setValue('s-cust-name', customer?.name || 'নগদ কাস্টমার');
    setValue('s-cust-phone', customer?.phone || '');
    if (customer?.category) setValue('s-cust-type', customer.category);
    updateCartPricesOnTypeChange();
}

function handleSalesProductSelect() {
    selectedProductForSale = getProduct(elementValue('s-item-search'));
    setValue('s-item-unit', selectedProductForSale?.unit || 'পিস');
    const type = elementValue('s-cust-type');
    setValue('s-item-price', selectedProductForSale
        ? (type === 'WHOLESALE' ? selectedProductForSale.wsPrice : selectedProductForSale.price)
        : '');
    calculateRowTotal();
}

function calculateRowTotal() {
    const price = Number(document.getElementById('s-item-price').value) || 0;
    const quantity = Number(document.getElementById('s-item-qty').value) || 0;
    setValue('s-item-total', Math.max(0, price * quantity).toFixed(2));
}

function updateCartPricesOnTypeChange() {
    const type = elementValue('s-cust-type');
    currentCart.forEach(item => {
        const product = getProduct(item.productId);
        if (product) item.price = Number(type === 'WHOLESALE' ? product.wsPrice : product.price) || item.price;
        item.total = item.price * item.qty;
    });
    handleSalesProductSelect();
    renderCart();
}

function addItemToCart() {
    try {
        const product = getProduct(elementValue('s-item-search'));
        if (!product) throw new Error('বিক্রির পণ্য নির্বাচন করুন।');
        const quantity = requireValidAmount(amountValue('s-item-qty'), 'পরিমাণ');
        const price = requireValidAmount(amountValue('s-item-price'), 'বিক্রয় দর', { allowZero: true });
        const existingQuantity = currentCart.filter(item => item.productId === product.id).reduce((sum, item) => sum + item.qty, 0);
        if (existingQuantity + quantity > Number(product.qty)) throw new Error('স্টকে পর্যাপ্ত পণ্য নেই।');
        const existingItem = currentCart.find(item => item.productId === product.id);
        if (existingItem) {
            existingItem.price = price;
            existingItem.qty += quantity;
            existingItem.total = existingItem.price * existingItem.qty;
        } else {
            currentCart.push({ productId: product.id, name: product.name, unit: product.unit || 'পিস', price, qty: quantity, total: price * quantity });
        }
        setValue('s-item-search', '');
        setValue('sales-product-filter', '');
        applyProductFilterForSales('');
        setValue('s-item-qty', '1');
        setValue('s-item-price', '');
        selectedProductForSale = null;
        calculateRowTotal();
        renderCart();
    } catch (error) {
        alert(error.message || 'কার্টে পণ্য যোগ করা যায়নি।');
    }
}

function removeCartItem(index) {
    currentCart.splice(index, 1);
    renderCart();
}

function renderCart() {
    const body = document.getElementById('cart-table-body');
    if (!body) return;
    body.innerHTML = currentCart.map((item, index) => `<tr>
        <td>${escapeHTML(item.name)}</td><td>${escapeHTML(item.unit)}</td>
        <td>${formatMoney(item.price)}</td><td>${formatMoney(item.qty)}</td><td>${formatMoney(item.total)}</td>
        <td><button class="btn btn-danger btn-sm" onclick="removeCartItem(${index})">বাদ</button></td>
    </tr>`).join('') || '<tr><td colspan="6" style="text-align:center;color:#888;">কার্ট খালি</td></tr>';
    const subTotal = currentCart.reduce((sum, item) => sum + item.total, 0);
    setValue('s-sub-total', subTotal.toFixed(2));
    calculateFinalSalesTotals();
}

async function checkoutSales() {
    try {
        if (!currentCart.length) throw new Error('কার্টে অন্তত একটি পণ্য যোগ করুন।');
        const cart = currentCart.map(item => ({ ...item }));
        for (const item of cart) {
            const product = getProduct(item.productId);
            if (!product || Number(product.qty) < item.qty) throw new Error(`${item.name}: স্টকে পর্যাপ্ত পণ্য নেই।`);
        }
        const shipping = requireValidAmount(amountValue('s-shipping'), 'পরিবহণ খরচ', { allowZero: true });
        const taxPercent = requireValidAmount(amountValue('s-tax-percent'), 'ট্যাক্স', { allowZero: true });
        const discount = requireValidAmount(amountValue('s-discount'), 'ডিসকাউন্ট', { allowZero: true });
        const subTotal = currentCart.reduce((sum, item) => sum + item.total, 0);
        const total = Math.max(0, subTotal + shipping + subTotal * taxPercent / 100 - discount);
        if (!Number.isFinite(total)) throw new Error('বিক্রয়ের মোট বিল গ্রহণযোগ্য সীমার বাইরে।');
        if (discount > subTotal + shipping + subTotal * taxPercent / 100) throw new Error('ডিসকাউন্ট সর্বমোট বিলের বেশি হতে পারবে না।');
        const paid = requireValidAmount(amountValue('s-paid-amount'), 'পরিশোধের টাকা', { allowZero: true });
        if (paid > total) throw new Error('পরিশোধের টাকা মোট বিলের বেশি হতে পারবে না।');
        setValue('s-grand-total', total.toFixed(2));
        const customerId = elementValue('s-customer-select');
        const isCashCustomer = !customerId || customerId === 'Walk-in';
        if (isCashCustomer && Math.abs(paid - total) > 0.009) throw new Error('বিল পরিশোধ অ্যামাউন্ট লিখুন');
        const customer = contacts.find(contact => contact.id === customerId);
        const record = {
            vCode: createUniqueVoucherNumber('INV'), date: todayISO(), customerId: customer?.id || null,
            customer: elementValue('s-cust-name') || 'নগদ কাস্টমার',
            phone: elementValue('s-cust-phone'), customerType: elementValue('s-cust-type'),
            items: cart, subTotal,
            shipping,
            taxPercent,
            discount,
            total, paid, due: total - paid
        };
        cart.forEach(item => {
            const product = getProduct(item.productId);
            product.qty = Number(product.qty) - item.qty;
        });
        salesHistory.push(record);
        await saveDataToServer();
        currentCart = [];
        setValue('s-shipping', '0');
        setValue('s-tax-percent', '0');
        setValue('s-discount', '0');
        setValue('s-paid-amount', '0');
        renderCart();
        refreshAllViews();
        showVoucherPreview(record, 'sale');
    } catch (error) {
        alert(error.message || 'বিক্রয় সম্পন্ন করা যায়নি।');
    }
}

function handleReturnTypeChange() {
    const type = elementValue('r-type');
    const customerReturn = type !== 'Supplier-Return';
    setText('r-party-label', customerReturn ? 'কাস্টমার নির্বাচন' : 'সাপ্লায়ার নির্বাচন');
    const parties = contacts.filter(contact => contact.type === (customerReturn ? 'Customer' : 'Supplier'));
    setOptions('r-party-select', parties.map(contact => ({ value: contact.id, label: contact.name })),
        customerReturn ? 'নগদ/সাধারণ ক্রেতা' : 'নগদ সরবরাহকারী', 'Walk-in');
    setValue('r-item-search', '');
    selectedProductForReturn = null;
    setValue('r-price', '');
    refreshReturnInvoiceOptions();
}

function getReturnInvoiceEntries(kind, partyKey, productId) {
    const customerReturn = kind === 'Customer-Return';
    const history = customerReturn ? salesHistory : purchaseHistory;
    const partyField = customerReturn ? 'customerId' : 'supplierId';
    const priceField = customerReturn ? 'price' : 'cost';
    const entries = history.flatMap(record => {
        const invoiceCode = record.vCode || record.vNo;
        const matchingLines = (record.items || []).filter(item => item.productId === productId);
        if (!invoiceCode || (record[partyField] || null) !== partyKey || !matchingLines.length) return [];
        return [{
            invoiceCode,
            date: record.date || '',
            quantity: matchingLines.reduce((sum, item) => sum + Number(item.qty || 0), 0),
            price: Number(matchingLines.at(-1)[priceField]) || 0,
            maxPrice: matchingLines.reduce((max, item) => Math.max(max, Number(item[priceField]) || 0), 0)
        }];
    }).sort((first, second) => first.date.localeCompare(second.date));

    let legacyQuantity = productReturns
        .filter(record => record.kind === kind && record.partyId === partyKey &&
            record.productId === productId && !record.sourceVoucherCode)
        .reduce((sum, record) => sum + Number(record.quantity || 0), 0);

    return entries.map(entry => {
        const returnedOnInvoice = productReturns
            .filter(record => record.kind === kind && record.partyId === partyKey &&
                record.productId === productId && record.sourceVoucherCode === entry.invoiceCode)
            .reduce((sum, record) => sum + Number(record.quantity || 0), 0);
        const allocatedLegacy = Math.min(entry.quantity, legacyQuantity);
        legacyQuantity -= allocatedLegacy;
        return {
            ...entry,
            remainingQuantity: Math.max(0, entry.quantity - returnedOnInvoice - allocatedLegacy)
        };
    }).filter(entry => entry.remainingQuantity > 0);
}

function refreshReturnInvoiceOptions() {
    const kind = elementValue('r-type');
    const selectedParty = elementValue('r-party-select');
    const partyKey = selectedParty && selectedParty !== 'Walk-in' ? selectedParty : null;
    const invoices = selectedProductForReturn
        ? getReturnInvoiceEntries(kind, partyKey, selectedProductForReturn.id)
        : [];
    setOptions('r-invoice-select', invoices.map(invoice => ({
        value: invoice.invoiceCode,
        label: `${invoice.invoiceCode} · ${invoice.date} · বাকি ${formatMoney(invoice.remainingQuantity)}`
    })), selectedProductForReturn ? '-- ইনভয়েস নির্বাচন করুন --' : '-- আগে পণ্য নির্বাচন করুন --');
    document.getElementById('r-invoice-select').disabled = !invoices.length;
    document.getElementById('r-qty').removeAttribute('max');
    setValue('r-price', '');
}

function handleReturnPartyChange() {
    refreshReturnInvoiceOptions();
}

function handleReturnInvoiceChange() {
    if (!selectedProductForReturn) return;
    const customerReturn = elementValue('r-type') === 'Customer-Return';
    const selectedParty = elementValue('r-party-select');
    const partyKey = selectedParty && selectedParty !== 'Walk-in' ? selectedParty : null;
    const invoiceCode = elementValue('r-invoice-select');
    const invoice = getReturnInvoiceEntries(elementValue('r-type'), partyKey, selectedProductForReturn.id)
        .find(entry => entry.invoiceCode === invoiceCode);
    const quantityInput = document.getElementById('r-qty');
    if (!invoice) {
        setValue('r-price', '');
        quantityInput.removeAttribute('max');
        return;
    }
    setValue('r-price', invoice.price);
    quantityInput.max = String(invoice.remainingQuantity);
    const quantity = Number(quantityInput.value);
    if (quantity > invoice.remainingQuantity) setValue('r-qty', invoice.remainingQuantity);
}

function searchProduct(query, context) {
    const resultBox = document.getElementById('return-search-results');
    if (selectedProductForReturn && selectedProductForReturn.name.toLowerCase() !== query.trim().toLowerCase()) {
        selectedProductForReturn = null;
    }
    if (!resultBox) return;
    const term = query.trim().toLowerCase();
    const matches = term ? products.filter(product => product.name.toLowerCase().includes(term)).slice(0, 10) : [];
    resultBox.innerHTML = matches.map(product => `<div onclick="selectReturnProduct('${escapeHTML(product.id)}')">${escapeHTML(product.name)} — ${escapeHTML(product.unit || 'পিস')}</div>`).join('');
    resultBox.style.display = matches.length ? 'block' : 'none';
}

function selectReturnProduct(id) {
    selectedProductForReturn = getProduct(id);
    if (!selectedProductForReturn) return;
    setValue('r-item-search', selectedProductForReturn.name);
    refreshReturnInvoiceOptions();
    document.getElementById('return-search-results').style.display = 'none';
}

async function submitProductReturn() {
    try {
        if (!selectedProductForReturn) throw new Error('রিটার্নের পণ্য খুঁজে নির্বাচন করুন।');
        const quantity = requireValidAmount(amountValue('r-qty'), 'রিটার্নের পরিমাণ');
        const price = requireValidAmount(amountValue('r-price'), 'রিটার্ন মূল্য', { allowZero: true });
        const kind = elementValue('r-type');
        const customerReturn = kind === 'Customer-Return';
        const product = getProduct(selectedProductForReturn.id);
        if (!product) throw new Error('পণ্যটি আর স্টকে নেই।');
        if (!customerReturn && Number(product.qty) < quantity) throw new Error('সাপ্লায়ারকে ফেরত দেওয়ার মতো স্টক নেই।');
        const partyId = elementValue('r-party-select');
        const party = contacts.find(contact => contact.id === partyId);
        const partyKey = party?.id || null;
        const invoiceCode = elementValue('r-invoice-select');
        const invoice = getReturnInvoiceEntries(kind, partyKey, product.id)
            .find(entry => entry.invoiceCode === invoiceCode);
        if (!invoice) throw new Error('রিটার্নের জন্য নির্দিষ্ট ইনভয়েস নির্বাচন করুন।');
        if (quantity > invoice.remainingQuantity) {
            throw new Error('নির্বাচিত ইনভয়েসে এই পরিমাণের পণ্য ফেরত দেওয়ার অবশিষ্ট নেই।');
        }
        if (price > invoice.maxPrice) throw new Error('রিটার্ন মূল্য নির্বাচিত ইনভয়েসের মূল দরের বেশি হতে পারবে না।');
        const record = {
            id: appId(), kind, date: todayISO(), partyId: partyKey,
            party: party?.name || (customerReturn ? 'নগদ/সাধারণ ক্রেতা' : 'নগদ সরবরাহকারী'),
            sourceVoucherCode: invoice.invoiceCode,
            productId: product.id, product: product.name, quantity, price, total: quantity * price
        };
        product.qty = Number(product.qty) + (customerReturn ? quantity : -quantity);
        productReturns.push(record);
        await saveDataToServer();
        setValue('r-item-search', '');
        setValue('r-qty', '1');
        setValue('r-price', '');
        selectedProductForReturn = null;
        refreshAllViews();
        alert('পণ্য রিটার্ন সংরক্ষণ হয়েছে।');
    } catch (error) {
        alert(error.message || 'রিটার্ন সংরক্ষণ করা যায়নি।');
    }
}

async function saveContact() {
    try {
        const name = elementValue('c-name');
        const type = elementValue('c-type');
        const openingDue = requireValidAmount(amountValue('c-opening-due'), 'প্রারম্ভিক বকেয়া', { allowZero: true });
        if (!name) throw new Error('কাস্টমার বা সাপ্লায়ারের নাম লিখুন।');
        if (contacts.some(contact => contact.type === type && contact.name.toLowerCase() === name.toLowerCase() && contact.phone === elementValue('c-phone'))) {
            throw new Error('এই নাম ও মোবাইলের পার্টি আগে থেকেই আছে।');
        }
        contacts.push({
            id: appId(), type, name, phone: elementValue('c-phone'), address: elementValue('c-address'),
            category: type === 'Customer' ? elementValue('c-cust-category') : null, openingDue
        });
        ['c-name', 'c-phone', 'c-address'].forEach(id => setValue(id, ''));
        setValue('c-opening-due', '0');
        await saveDataToServer();
        refreshAllViews();
        alert('পার্টি সংরক্ষণ হয়েছে।');
    } catch (error) {
        alert(error.message || 'পার্টি সংরক্ষণ করা যায়নি।');
    }
}

function contactBalance(contact) {
    if (contact.type === 'Customer') {
        const salesDue = salesHistory.filter(record => record.customerId === contact.id).reduce((sum, record) => sum + Number(record.due || 0), 0);
        const returns = productReturns.filter(record => record.kind === 'Customer-Return' && record.partyId === contact.id).reduce((sum, record) => sum + Number(record.total || 0), 0);
        const payments = dueTransactions.filter(record => record.type === 'Customer' && record.partyId === contact.id).reduce((sum, record) => sum + Number(record.amount || 0), 0);
        return Math.max(0, Number(contact.openingDue || 0) + salesDue - returns - payments);
    }
    const purchaseDue = purchaseHistory.filter(record => record.supplierId === contact.id).reduce((sum, record) => sum + Number(record.due || 0), 0);
    const returns = productReturns.filter(record => record.kind === 'Supplier-Return' && record.partyId === contact.id).reduce((sum, record) => sum + Number(record.total || 0), 0);
    const payments = dueTransactions.filter(record => record.type === 'Supplier' && record.partyId === contact.id).reduce((sum, record) => sum + Number(record.amount || 0), 0);
    return Math.max(0, Number(contact.openingDue || 0) + purchaseDue - returns - payments);
}

function handleDueActionTypeChange() {
    const type = elementValue('due-action-type');
    const parties = contacts.filter(contact => contact.type === type);
    setText('due-party-label', type === 'Customer' ? 'কাস্টমার নির্বাচন করুন' : type === 'Supplier' ? 'সাপ্লায়ার নির্বাচন করুন' : 'পার্টি নির্বাচন করুন');
    setText('due-amount-label', type === 'Customer' ? 'আদায়ের পরিমাণ (৳)' : 'পরিশোধের পরিমাণ (৳)');
    setOptions('due-party-select', parties.map(contact => ({ value: contact.id, label: contact.name })), '-- সিলেক্ট করুন --');
    document.getElementById('due-party-select').disabled = !type;
    document.getElementById('due-transaction-amount').disabled = !type;
    updateDueTransactionIndicator();
}

function updateDueTransactionIndicator() {
    const type = elementValue('due-action-type');
    const party = contacts.find(contact => contact.id === elementValue('due-party-select') && contact.type === type);
    setValue('due-current-balance', party ? contactBalance(party).toFixed(2) : '0');
}

async function submitDueTransaction() {
    try {
        const type = elementValue('due-action-type');
        const party = contacts.find(contact => contact.id === elementValue('due-party-select') && contact.type === type);
        if (!party) throw new Error('লেনদেনের ধরন ও পার্টি নির্বাচন করুন।');
        const amount = requireValidAmount(amountValue('due-transaction-amount'), 'লেনদেনের পরিমাণ');
        const balance = contactBalance(party);
        if (amount > balance) throw new Error('লেনদেনের পরিমাণ বর্তমান বকেয়ার চেয়ে বেশি হতে পারবে না।');
        dueTransactions.push({ id: appId(), type, partyId: party.id, amount, date: todayISO() });
        await saveDataToServer();
        setValue('due-transaction-amount', '');
        updateDueTransactionIndicator();
        refreshAllViews();
        alert('লেনদেন সংরক্ষণ হয়েছে।');
    } catch (error) {
        alert(error.message || 'লেনদেন সংরক্ষণ করা যায়নি।');
    }
}

function openContactEdit(id) {
    const contact = contacts.find(item => item.id === id);
    if (!contact) return;
    setValue('edit-contact-id', id);
    setValue('edit-contact-name', contact.name);
    setValue('edit-contact-phone', contact.phone);
    setValue('edit-contact-address', contact.address);
    setValue('edit-contact-cat', contact.category || 'RETAIL');
    document.getElementById('edit-contact-cat-group').style.display = contact.type === 'Customer' ? 'flex' : 'none';
    setText('edit-contact-title-label', contact.type === 'Customer' ? 'কাস্টমার' : 'সাপ্লায়ার');
    document.getElementById('contact-edit-modal').style.display = 'block';
}

async function updateContactData() {
    const contact = contacts.find(item => item.id === elementValue('edit-contact-id'));
    if (!contact) return alert('সম্পাদনার পার্টি পাওয়া যায়নি।');
    const name = elementValue('edit-contact-name');
    if (!name) return alert('নাম লিখুন।');
    if (contacts.some(item => item.id !== contact.id && item.type === contact.type &&
        item.name.toLowerCase() === name.toLowerCase() && item.phone === elementValue('edit-contact-phone'))) {
        return alert('এই নাম ও মোবাইলের পার্টি আগে থেকেই আছে।');
    }
    contact.name = name;
    contact.phone = elementValue('edit-contact-phone');
    contact.address = elementValue('edit-contact-address');
    if (contact.type === 'Customer') contact.category = elementValue('edit-contact-cat');
    try {
        await saveDataToServer();
        document.getElementById('contact-edit-modal').style.display = 'none';
        refreshAllViews();
        alert('পার্টির তথ্য আপডেট হয়েছে।');
    } catch (error) {
        showSaveError(error, 'পার্টির তথ্য সংরক্ষণ করা যায়নি');
    }
}

function openContactProfile(id) {
    const contact = contacts.find(item => item.id === id);
    if (!contact) return;
    setText('prof-type-title', contact.type === 'Customer' ? 'কাস্টমার' : 'সাপ্লায়ার');
    setText('prof-name', contact.name);
    setText('prof-phone', contact.phone || '—');
    setText('prof-due', formatMoney(contactBalance(contact)));
    setText('prof-company-title', storeConfig.companyName);
    const rows = [];
    const history = contact.type === 'Customer' ? salesHistory : purchaseHistory;
    history.filter(record => (contact.type === 'Customer' ? record.customerId : record.supplierId) === contact.id)
        .forEach(record => rows.push({ code: record.vCode || record.vNo, date: record.date, total: record.total, paid: record.paid, due: record.due }));
    dueTransactions.filter(record => record.partyId === contact.id).forEach(record =>
        rows.push({ code: record.type === 'Customer' ? 'বকেয়া আদায়' : 'বকেয়া পরিশোধ', date: record.date, total: record.amount, paid: record.amount, due: 0 }));
    const body = document.querySelector('#prof-history-table tbody');
    body.innerHTML = rows.map(row => `<tr><td>${escapeHTML(row.code || '')}</td><td>${escapeHTML(row.date || '')}</td>
        <td>${formatMoney(row.total)}</td><td>${formatMoney(row.paid)}</td><td>${formatMoney(row.due)}</td></tr>`).join('') ||
        '<tr><td colspan="5">কোনো লেনদেন নেই।</td></tr>';
    document.getElementById('party-profile-preview').style.display = 'block';
}

function printLedger() {
    document.body.classList.add('print-ledger');
    window.addEventListener('afterprint', () => document.body.classList.remove('print-ledger'), { once: true });
    window.print();
}

function searchStockProduct(query) {
    const box = document.getElementById('stock-search-results');
    const term = query.trim().toLowerCase();
    const matches = term ? products.filter(product => product.name.toLowerCase().includes(term)).slice(0, 10) : [];
    box.innerHTML = matches.map(product => `<div onclick="showStockProduct('${escapeHTML(product.id)}')">${escapeHTML(product.name)}</div>`).join('');
    box.style.display = matches.length ? 'block' : 'none';
}

function showStockProduct(id) {
    const product = getProduct(id);
    if (!product) return;
    setText('st-name', product.name);
    setText('st-unit', product.unit || 'পিস');
    setText('st-unit-display', product.unit || 'পিস');
    setText('st-price', formatMoney(product.price));
    setText('st-ws-price', formatMoney(product.wsPrice));
    setText('st-qty', formatMoney(product.qty));
    document.getElementById('stock-display-box').style.display = 'block';
    document.getElementById('stock-search-results').style.display = 'none';
}

function openProductEdit(id) {
    const product = getProduct(id);
    if (!product) return;
    setValue('edit-prod-id', id);
    setValue('edit-prod-name', product.name);
    setValue('edit-prod-unit', product.unit || 'পিস');
    setValue('edit-prod-cost', product.cost);
    setValue('edit-prod-price', product.price);
    setValue('edit-prod-wsprice', product.wsPrice);
    setValue('edit-prod-qty', product.qty);
    document.getElementById('product-edit-modal').style.display = 'block';
}

async function updateProductData() {
    try {
        const product = getProduct(elementValue('edit-prod-id'));
        if (!product) throw new Error('সম্পাদনার পণ্য পাওয়া যায়নি।');
        const name = elementValue('edit-prod-name');
        const unit = elementValue('edit-prod-unit');
        const cost = requireValidAmount(amountValue('edit-prod-cost'), 'ক্রয়মূল্য', { allowZero: true });
        const price = requireValidAmount(amountValue('edit-prod-price'), 'খুচরা মূল্য', { allowZero: true });
        const wsPrice = requireValidAmount(amountValue('edit-prod-wsprice'), 'পাইকারী মূল্য', { allowZero: true });
        const quantity = requireValidAmount(amountValue('edit-prod-qty'), 'মজুদ পরিমাণ', { allowZero: true });
        if (!name || !unit) throw new Error('পণ্যের নাম ও ইউনিট দিতে হবে।');
        if (products.some(item => item.id !== product.id && item.name.toLowerCase() === name.toLowerCase())) {
            throw new Error('এই নামে অন্য একটি পণ্য আগে থেকেই আছে।');
        }
        const oldName = product.name;
        Object.assign(product, { name, unit, cost, price, wsPrice, qty: quantity });
        const catalogItem = productCatalog.find(item => item.id === product.catalogId || item.name === oldName);
        if (catalogItem) {
            catalogItem.name = name;
            catalogItem.unit = unit;
            product.catalogId = catalogItem.id;
        }
        await saveDataToServer();
        document.getElementById('product-edit-modal').style.display = 'none';
        refreshAllViews();
        alert('পণ্যের তথ্য আপডেট হয়েছে।');
    } catch (error) {
        alert(error.message || 'পণ্যের তথ্য আপডেট করা যায়নি।');
    }
}

async function deleteStockProduct(id) {
    const product = getProduct(id);
    if (!product) return;
    if (Number(product.qty) !== 0) return alert('স্টকে পণ্য থাকলে মুছতে পারবেন না।');
    if (purchaseHistory.some(record => record.items?.some(item => item.productId === id)) ||
        salesHistory.some(record => record.items?.some(item => item.productId === id))) {
        return alert('লেনদেনের ইতিহাসে থাকা পণ্য মুছবেন না; পণ্য তালিকা থেকে সরান।');
    }
    if (!confirm(`“${product.name}” মুছবেন?`)) return;
    products = products.filter(item => item.id !== id);
    try { await saveDataToServer(); refreshAllViews(); } catch (error) { showSaveError(error, 'পণ্য মুছা যায়নি'); }
}

async function deleteAllZeroStockProducts() {
    const removable = products.filter(product => Number(product.qty) === 0 && !purchaseHistory.some(record => record.items?.some(item => item.productId === product.id)) && !salesHistory.some(record => record.items?.some(item => item.productId === product.id)));
    if (!removable.length) return alert('শুধু শূন্য-স্টক পণ্য গুলি মুছতে পারবেন।');
    if (!confirm(`${removable.length}টি শূন্য-স্টক পণ্য মুছবেন?`)) return;
    products = products.filter(product => !removable.some(item => item.id === product.id));
    try { await saveDataToServer(); refreshAllViews(); alert('শূন্য-স্টক পণ্য মুছে দেওয়া হয়েছে।'); } catch (error) { showSaveError(error, 'শূন্য-স্টক পণ্য মুছে দেওয়া যায়নি'); }
}

function showVoucherPreview(record, kind) {
    const isSale = kind === 'sale';
    setText('v-comp-name', storeConfig.companyName);
    setText('v-comp-subtitle', storeConfig.subtitle || (isSale ? 'ক্যাশ মেমো' : 'ক্রয় ভাউচার'));
    setText('v-comp-address', storeConfig.address || '');
    setText('v-code', isSale ? record.vCode : record.vNo);
    setText('v-party-type-label', isSale ? 'ক্রেতার নাম:' : 'সরবরাহকারীর নাম:');
    setText('v-cust', isSale ? record.customer : record.supplier);
    setText('v-seller', currentUsername || '');
    setText('v-phone', isSale ? record.phone || '' : '');
    setText('v-date', record.date || todayISO());
    const logo = document.getElementById('v-logo-img');
    logo.src = storeConfig.logoData || '';
    logo.style.display = storeConfig.logoData ? 'block' : 'none';
    const body = document.querySelector('#v-table tbody');
    body.innerHTML = (record.items || []).map(item => `<tr>
        <td>${escapeHTML(item.name)}</td><td>${escapeHTML(item.unit || 'পিস')}</td>
        <td>${formatMoney(isSale ? item.price : item.cost)}</td><td>${formatMoney(item.qty)}</td><td>${formatMoney(item.total)}</td>
    </tr>`).join('');
    const subTotal = record.subTotal ?? record.total;
    setText('v-sub-total-val', formatMoney(subTotal));
    setText('v-shipping-val', formatMoney(record.shipping));
    setText('v-tax-rate', formatMoney(record.taxPercent));
    setText('v-tax-val', formatMoney(Number(record.subTotal || 0) * Number(record.taxPercent || 0) / 100));
    setText('v-discount-val', formatMoney(record.discount));
    document.getElementById('v-shipping-row').style.display = Number(record.shipping) ? 'block' : 'none';
    document.getElementById('v-tax-row').style.display = Number(record.taxPercent) ? 'block' : 'none';
    document.getElementById('v-discount-row').style.display = Number(record.discount) ? 'block' : 'none';
    setText('v-grand-total-val', formatMoney(record.total));
    setText('v-paid', formatMoney(record.paid));
    setText('v-due', formatMoney(record.due));
    const contact = contacts.find(item => item.id === (isSale ? record.customerId : record.supplierId));
    const dueSection = document.getElementById('v-party-due-section');
    dueSection.style.display = contact ? 'block' : 'none';
    if (contact) {
        setText('v-prev-due-val', formatMoney(Math.max(0, contactBalance(contact) - Number(record.due || 0))));
        setText('v-curr-due-val', formatMoney(record.due));
        setText('v-total-due-val', formatMoney(contactBalance(contact)));
        setText('v-total-due-label', isSale ? 'সর্বমোট পাওনা' : 'সর্বমোট দেনা');
        setText('v-curr-due-row', isSale ? 'এই বিলে বকেয়া (পাওনা)' : 'এই বিলে বকেয়া (দেনা)');
    }
    document.getElementById('voucher-preview').style.display = 'block';
}

function searchVoucherForReprint() {
    const code = elementValue('voucher-search-number').toLowerCase();
    const purchase = purchaseHistory.find(record => record.vNo?.toLowerCase() === code);
    const sale = salesHistory.find(record => record.vCode?.toLowerCase() === code);
    if (purchase) return showVoucherPreview(purchase, 'purchase');
    if (sale) return showVoucherPreview(sale, 'sale');
    alert('এই নম্বরের কোনো ভাউচার পাওয়া যায়নি।');
}

function printVoucher() {
    document.body.classList.add('print-voucher');
    window.addEventListener('afterprint', () => document.body.classList.remove('print-voucher'), { once: true });
    window.print();
}

function previewAndStoreLogo(input) {
    const file = input.files?.[0];
    if (!file) return;
    if (!file.type.startsWith('image/')) return alert('একটি image ফাইল নির্বাচন করুন।');
    if (file.size > 2 * 1024 * 1024) return alert('লোগো ফাইল ২ MB-এর মধ্যে হতে হবে।');
    const reader = new FileReader();
    reader.onerror = () => alert('লোগো ফাইল পড়া যায়নি।');
    reader.onload = async () => {
        storeConfig.logoData = String(reader.result);
        applySettingsToUI();
        try { await saveDataToServer(); } catch (error) { showSaveError(error, 'লোগো সংরক্ষণ করা যায়নি'); }
    };
    reader.readAsDataURL(file);
}

async function saveSettingsProfile() {
    const companyName = elementValue('settings-comp-name');
    if (!companyName) return alert('প্রতিষ্ঠানের নাম লিখুন।');
    storeConfig.companyName = companyName;
    storeConfig.subtitle = elementValue('settings-comp-subtitle');
    storeConfig.address = elementValue('settings-comp-address');
    try {
        await saveDataToServer();
        applySettingsToUI();
        alert('প্রোফাইল সেটিংস সংরক্ষণ হয়েছে।');
    } catch (error) {
        showSaveError(error, 'প্রোফাইল সেটিংস সংরক্ষণ করা যায়নি');
    }
}

function exportSystemData() {
    try {
        const backup = {
            format: 'shop-management-backup',
            version: 2,
            exportedAt: new Date().toISOString(),
            data: buildAllData()
        };
        const url = URL.createObjectURL(new Blob([JSON.stringify(backup, null, 2)], { type: 'application/json' }));
        const link = document.createElement('a');
        link.href = url;
        link.download = `shop-backup-${todayISO()}.json`;
        document.body.appendChild(link);
        link.click();
        link.remove();
        setTimeout(() => URL.revokeObjectURL(url), 0);
    } catch (error) {
        alert(`ব্যাকআপ তৈরি করা যায়নি: ${error.message || error}`);
    }
}

function downloadCsvBackup() {
    try {
        const backup = buildAllData();
        const rows = [[
            'section', 'id', 'name', 'unit', 'qty', 'cost', 'price', 'wsPrice', 'date', 'party', 'total', 'paid', 'due'
        ]];
        (backup.products || []).forEach(product => rows.push([
            'product', product.id, product.name, product.unit || 'পিস', product.qty ?? 0, product.cost ?? 0, product.price ?? 0, product.wsPrice ?? 0, '', '', '', '', ''
        ]));
        (backup.contacts || []).forEach(contact => rows.push([
            'contact', contact.id, contact.name, contact.type || '', '', '', '', '', '', contact.name, '', '', ''
        ]));
        (backup.purchaseHistory || []).forEach(record => rows.push([
            'purchase', record.vNo || '', record.supplier || '', '', '', '', '', '', record.date || '', record.supplier || '', record.total ?? 0, record.paid ?? 0, record.due ?? 0
        ]));
        (backup.salesHistory || []).forEach(record => rows.push([
            'sale', record.vCode || '', record.customer || '', '', '', '', '', '', record.date || '', record.customer || '', record.total ?? 0, record.paid ?? 0, record.due ?? 0
        ]));
        const csv = rows.map(row => row.map(value => escapeCsvValue(value)).join(',')).join('\n');
        const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = `shop-csv-backup-${todayISO()}.csv`;
        document.body.appendChild(link);
        link.click();
        link.remove();
        setTimeout(() => URL.revokeObjectURL(url), 0);
        alert('CSV ব্যাকআপ ডাউনলোড হয়েছে।');
    } catch (error) {
        alert(`CSV ব্যাকআপ তৈরি করা যায়নি: ${error.message || error}`);
    }
}

async function importSystemData() {
    const file = document.getElementById('import-json-file').files?.[0];
    if (!file) return alert('JSON ব্যাকআপ ফাইল নির্বাচন করুন।');
    try {
        const parsed = JSON.parse(await file.text());
        const data = parsed?.format === 'shop-management-backup' ? parsed.data : parsed;
        if (!data || typeof data !== 'object' || Array.isArray(data)) throw new Error('ব্যাকআপ JSON-এর গঠন সঠিক নয়।');
        for (const key of ['products', 'contacts', 'purchaseHistory', 'salesHistory']) {
            if (!Array.isArray(data[key])) throw new Error(`ব্যাকআপে ${key} তালিকা নেই বা সঠিক নয়।`);
        }
        if (data.productCatalog !== undefined && !Array.isArray(data.productCatalog)) {
            throw new Error('ব্যাকআপে productCatalog তালিকা সঠিক নয়।');
        }
        if (!confirm('বর্তমান পণ্যের তালিকা ও লেনদেন ব্যাকআপের ডেটা দিয়ে প্রতিস্থাপন করবেন?')) return;
        loadLocalDataObject(data);
        await saveDataToServer();
        applySettingsToUI();
        refreshAllViews();
        document.getElementById('import-json-file').value = '';
        alert('ব্যাকআপ ডেটা রিস্টোর হয়েছে।');
    } catch (error) {
        alert(`ব্যাকআপ রিস্টোর করা যায়নি: ${error.message || error}`);
    }
}

function normalizeCsvHeader(value) {
    return String(value ?? '').trim().toLowerCase().replace(/[\s_\-]+/g, '');
}

function parseCsvText(csvText) {
    const lines = csvText.split(/\r?\n/).filter(line => line.trim());
    if (!lines.length) return [];
    const rows = [];
    let current = [];
    let inQuotes = false;
    let buffer = '';
    const flushCell = () => {
        current.push(buffer);
        buffer = '';
    };
    for (const line of lines) {
        for (let index = 0; index < line.length; index += 1) {
            const char = line[index];
            if (char === '"') {
                if (inQuotes && line[index + 1] === '"') {
                    buffer += '"';
                    index += 1;
                } else {
                    inQuotes = !inQuotes;
                }
            } else if (char === ',' && !inQuotes) {
                flushCell();
            } else {
                buffer += char;
            }
        }
        flushCell();
        rows.push(current);
        current = [];
    }
    return rows;
}

async function importCsvInventory() {
    const file = document.getElementById('csv-import-file')?.files?.[0];
    if (!file) return alert('CSV ফাইল নির্বাচন করুন।');
    try {
        const text = await file.text();
        const rows = parseCsvText(text);
        if (rows.length < 2) throw new Error('CSV ফাইলে কোনো ডেটা নেই।');
        const headers = rows[0].map(normalizeCsvHeader);
        const indexOf = (...names) => headers.findIndex(header => names.includes(header));
        const nameIndex = indexOf('name', 'product', 'productname', 'পণ্যেরনাম', 'itemname');
        const unitIndex = indexOf('unit', 'ইউনিট');
        const qtyIndex = indexOf('qty', 'quantity', 'stock', 'পরিমাণ', 'মজুদ');
        const costIndex = indexOf('cost', 'purchaseprice', 'ক্রয়মূল্য');
        const priceIndex = indexOf('price', 'retailprice', 'খুচরামূল্য');
        const wsPriceIndex = indexOf('wsprice', 'wholesaleprice', 'পাইকারিমূল্য');
        if (nameIndex === -1) throw new Error('CSV-এ পণ্যের নামের কলাম পাওয়া যায়নি।');
        let imported = 0;
        for (let rowIndex = 1; rowIndex < rows.length; rowIndex += 1) {
            const row = rows[rowIndex];
            const name = String(row[nameIndex] || '').trim();
            if (!name) continue;
            const unit = String(row[unitIndex] || 'পিস').trim() || 'পিস';
            const qty = Number(row[qtyIndex] || 0);
            const cost = Number(row[costIndex] || 0);
            const price = Number(row[priceIndex] || 0);
            const wsPrice = Number(row[wsPriceIndex] || 0);
            const catalog = productCatalog.find(item => item.name.toLowerCase() === name.toLowerCase()) || { id: appId(), name, unit };
            if (!productCatalog.some(item => item.id === catalog.id)) {
                productCatalog.push(catalog);
            }
            const current = products.find(item => item.catalogId === catalog.id || item.name.toLowerCase() === name.toLowerCase());
            if (current) {
                current.name = name;
                current.unit = unit;
                current.qty = Number.isFinite(qty) ? Math.max(0, qty) : Number(current.qty || 0);
                current.cost = Number.isFinite(cost) ? cost : Number(current.cost || 0);
                current.price = Number.isFinite(price) ? price : Number(current.price || 0);
                current.wsPrice = Number.isFinite(wsPrice) ? wsPrice : Number(current.wsPrice || 0);
                current.catalogId = catalog.id;
            } else {
                products.push({
                    id: appId(), catalogId: catalog.id, name, unit,
                    cost: Number.isFinite(cost) ? cost : 0,
                    price: Number.isFinite(price) ? price : 0,
                    wsPrice: Number.isFinite(wsPrice) ? wsPrice : 0,
                    qty: Number.isFinite(qty) ? Math.max(0, qty) : 0
                });
            }
            imported += 1;
        }
        if (!imported) throw new Error('CSV-এ কোনো বৈধ পণ্য পাওয়া যায়নি।');
        await saveDataToServer();
        refreshAllViews();
        document.getElementById('csv-import-file').value = '';
        alert(`CSV থেকে ${imported}টি পণ্য আপডেট হয়েছে।`);
    } catch (error) {
        alert(`CSV import ব্যর্থ: ${error.message || error}`);
    }
}

function uploadProductExcel(event) {
    const file = event.target.files?.[0];
    if (!file) return;
    if (typeof XLSX === 'undefined') {
        alert('Excel লাইব্রেরি লোড হয়নি। Excel import করতে ইন্টারনেট সংযোগ দিয়ে পেজটি আবার খুলুন।');
        event.target.value = '';
        return;
    }
    const reader = new FileReader();
    reader.onerror = () => alert('Excel ফাইল পড়া যায়নি।');
    reader.onload = async () => {
        try {
            const workbook = XLSX.read(reader.result, { type: 'array' });
            const firstSheet = workbook.Sheets[workbook.SheetNames[0]];
            const rows = XLSX.utils.sheet_to_json(firstSheet, { defval: '' });
            if (!rows.length) throw new Error('Excel ফাইলে কোনো পণ্য নেই।');
            const header = value => String(value).toLowerCase().replace(/[\s_-]/g, '');
            const find = (row, names) => {
                const key = Object.keys(row).find(column => names.includes(header(column)));
                return key ? row[key] : '';
            };
            let validRows = 0;
            let added = 0;
            for (const row of rows) {
                const name = String(find(row, ['name', 'product', 'productname', 'পণ্যেরনাম'])).trim();
                if (!name) continue;
                validRows++;
                const unit = String(find(row, ['unit', 'ইউনিট']) || 'পিস').trim();
                let catalog = productCatalog.find(item => item.name.toLowerCase() === name.toLowerCase());
                if (!catalog) {
                    catalog = { id: appId(), name, unit };
                    productCatalog.push(catalog);
                    added++;
                }
                const existing = products.find(product => product.catalogId === catalog.id || product.name.toLowerCase() === name.toLowerCase());
                const readNumber = names => {
                    const value = find(row, names);
                    if (value === '' || value === null || value === undefined) return NaN;
                    const number = Number(value);
                    return Number.isFinite(number) ? number : NaN;
                };
                const cost = readNumber(['cost', 'purchaseprice', 'ক্রয়মূল্য']);
                const price = readNumber(['price', 'retailprice', 'খুচরামূল্য']);
                const wsPrice = readNumber(['wsprice', 'wholesaleprice', 'পাইকারিমূল্য']);
                const qty = readNumber(['qty', 'quantity', 'stock', 'পরিমাণ', 'মজুদ']);
                if (existing) {
                    if (Number.isFinite(cost) && cost >= 0) existing.cost = cost;
                    if (Number.isFinite(price) && price >= 0) existing.price = price;
                    if (Number.isFinite(wsPrice) && wsPrice >= 0) existing.wsPrice = wsPrice;
                    if (Number.isFinite(qty) && qty >= 0) existing.qty = qty;
                    existing.catalogId = catalog.id;
                    existing.unit = unit;
                } else if (Number.isFinite(qty) && qty > 0) {
                    products.push({
                        id: appId(), catalogId: catalog.id, name, unit,
                        cost: Number.isFinite(cost) && cost >= 0 ? cost : 0,
                        price: Number.isFinite(price) && price >= 0 ? price : 0,
                        wsPrice: Number.isFinite(wsPrice) && wsPrice >= 0 ? wsPrice : 0,
                        qty
                    });
                }
            }
            if (!validRows) throw new Error('Excel থেকে কোনো বৈধ পণ্যের নাম পাওয়া যায়নি।');
            await saveDataToServer();
            refreshAllViews();
            alert('Excel থেকে পণ্য আমদানি হয়েছে।');
        } catch (error) {
            alert(`Excel import করা যায়নি: ${error.message || error}`);
        } finally {
            event.target.value = '';
        }
    };
    reader.readAsArrayBuffer(file);
}

function downloadProductExcel() {
    if (typeof XLSX === 'undefined') {
        alert('Excel লাইব্রেরি লোড হয়নি। Excel export করতে ইন্টারনেট সংযোগ দিয়ে পেজটি আবার খুলুন।');
        return;
    }
    const rows = productCatalog.map(item => {
        const product = products.find(record => record.catalogId === item.id || record.name === item.name);
        return {
        'পণ্যের নাম': item.name, 'ইউনিট': item.unit || product?.unit || 'পিস',
        'ক্রয়মূল্য': product?.cost ?? 0, 'খুচরা মূল্য': product?.price ?? 0,
        'পাইকারী মূল্য': product?.wsPrice ?? 0, 'মজুদ': product?.qty ?? 0
        };
    });
    const workbook = XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(workbook, XLSX.utils.json_to_sheet(rows), 'পণ্য তালিকা');
    XLSX.writeFile(workbook, 'product-list.xlsx');
}

function openContactLedger(type) {
    contactLedgerMode = type;
    switchTab('contacts-tab');
    configureContactLedger(type);
    document.querySelectorAll('.menu-btn').forEach(button => button.classList.remove('active'));
    document.getElementById(type === 'Customer' ? 'btn-customer-ledger' : 'btn-supplier-ledger')?.classList.add('active');
}

function configureContactLedger(type) {
    contactLedgerMode = type;
    setValue('c-type', type);
    document.getElementById('c-type').disabled = true;
    setText('contact-ledger-title', type === 'Customer' ? '👤 কাস্টমার খাতা' : '🏢 সাপ্লায়ার খাতা');
    document.getElementById('c-cust-category-group').style.display = type === 'Customer' ? 'flex' : 'none';
    document.getElementById('customer-ledger-list').style.display = type === 'Customer' ? 'block' : 'none';
    document.getElementById('supplier-ledger-list').style.display = type === 'Supplier' ? 'block' : 'none';
    handleDueActionTypeChange();
}

function toggleSubmenu(submenuId, arrowId) {
    const submenu = document.getElementById(submenuId);
    const arrow = document.getElementById(arrowId);
    if (!submenu || !arrow) return;
    submenu.classList.toggle('open');
    arrow.textContent = submenu.classList.contains('open') ? '▲' : '▼';
}

function closeSubmenu(submenuId, arrowId) {
    const submenu = document.getElementById(submenuId);
    const arrow = document.getElementById(arrowId);
    if (submenu && arrow) {
        submenu.classList.remove('open');
        arrow.textContent = '▼';
    }
}
