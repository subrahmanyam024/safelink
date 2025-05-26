
// Global variables
let currentAnalysis = null;
let analysisSteps = ['Redirect Check', 'URL Structure', 'API Security Check', 'SSL Analysis', 'Final Report'];
let currentStep = 0;

// Utility Functions
function isValidURL(string) {
    try {
        new URL(string);
        return true;
    } catch (_) {
        return false;
    }
}

function extractDomain(url) {
    try {
        return new URL(url).hostname.toLowerCase();
    } catch (_) {
        return '';
    }
}

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

// Enhanced URL Structure Analysis
function analyzeURLStructure(url, isHttp = false) {
    const results = [];
    const domain = extractDomain(url);
    const urlObj = new URL(url);
    
    if (!isHttp) {
        if (url.startsWith('https://')) {
            results.push({
                type: 'good',
                icon: '🔒',
                text: 'Uses secure HTTPS connection',
                weight: 15
            });
        } else if (url.startsWith('http://')) {
            results.push({
                type: 'warning',
                icon: '⚠️',
                text: 'Uses unsecured HTTP connection',
                weight: -15
            });
        }
    }
    
    const ipPattern = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
    if (ipPattern.test(domain)) {
        results.push({
            type: 'danger',
            icon: '🚨',
            text: 'Uses IP address instead of domain name - High Risk!',
            weight: -30
        });
    }
    
    if (domain.length > 50) {
        results.push({
            type: 'warning',
            icon: '📏',
            text: 'Unusually long domain name detected',
            weight: -10
        });
    }
    
    const subdomains = domain.split('.');
    if (subdomains.length > 4) {
        results.push({
            type: 'warning',
            icon: '🔗',
            text: 'Multiple subdomains detected - be cautious',
            weight: -8
        });
    }
    
    const suspiciousPatterns = [
        { pattern: /[0-9]{4,}/, text: 'Contains long number sequences', weight: -7 },
        { pattern: /[-_]{3,}/, text: 'Contains multiple dashes/underscores', weight: -5 },
        { pattern: /[a-z]{20,}/, text: 'Contains very long text strings', weight: -5 }
    ];
    
    suspiciousPatterns.forEach(({ pattern, text, weight }) => {
        if (pattern.test(url)) {
            results.push({
                type: 'warning',
                icon: '🔍',
                text: text,
                weight: weight
            });
        }
    });
    
    return results;
}

// Enhanced Phishing Detection
function analyzePhishingPatterns(url) {
    const results = [];
    const domain = extractDomain(url);
    const urlLower = url.toLowerCase();
    
    const phishingKeywords = [
        'secure', 'verify', 'update', 'confirm', 'account',
        'bank', 'paypal', 'amazon', 'apple', 'microsoft',
        'login', 'signin', 'suspended', 'limited', 'expire'
    ];
    
    const suspiciousKeywords = phishingKeywords.filter(keyword => {
        return urlLower.includes(keyword) && 
               !domain.includes(keyword) && 
               !isLegitimateService(domain, keyword);
    });
    
    if (suspiciousKeywords.length > 0) {
        results.push({
            type: 'warning',
            icon: '🎣',
            text: `Contains suspicious keywords: ${suspiciousKeywords.join(', ')}`,
            weight: -15
        });
    }
    
    const legitimateDomains = [
        'google.com', 'facebook.com', 'amazon.com', 'apple.com',
        'microsoft.com', 'paypal.com', 'ebay.com', 'netflix.com',
        'instagram.com', 'twitter.com', 'linkedin.com'
    ];
    
    legitimateDomains.forEach(legitDomain => {
        if (isSimilarDomain(domain, legitDomain) && domain !== legitDomain) {
            results.push({
                type: 'danger',
                icon: '🎭',
                text: `Similar to legitimate domain "${legitDomain}" - Possible phishing!`,
                weight: -25
            });
        }
    });
    
    if (domain.includes('xn--')) {
        results.push({
            type: 'warning',
            icon: '🌐',
            text: 'Uses internationalized domain name - verify carefully',
            weight: -8
        });
    }
    
    return results;
}

// Real API Integration Functions
async function performRealAPIChecks(url) {
    const results = [];
    
    console.log('Starting real API checks for:', url);
    
    if (typeof securityAPI === 'undefined') {
        console.error('Security API handler not found');
        return [{
            type: 'warning',
            icon: '⚠️',
            text: 'API services temporarily unavailable',
            weight: 0
        }];
    }
    
    try {
        const virusTotalPromise = securityAPI.checkVirusTotal(url)
            .catch(error => {
                console.error('VirusTotal error:', error);
                return [{
                    type: 'warning',
                    icon: '🔍',
                    text: 'VirusTotal scan unavailable - check connection',
                    weight: 0
                }];
            });
        
        const safeBrowsingPromise = securityAPI.checkSafeBrowsing(url)
            .catch(error => {
                console.error('Safe Browsing error:', error);
                return [{
                    type: 'warning',
                    icon: '🛡️',
                    text: 'Google Safe Browsing check unavailable',
                    weight: 0
                }];
            });
        
        console.log('Waiting for API responses...');
        const [virusTotalResults, safeBrowsingResults] = await Promise.all([
            virusTotalPromise,
            safeBrowsingPromise
        ]);
        
        console.log('VirusTotal results:', virusTotalResults);
        console.log('Safe Browsing results:', safeBrowsingResults);
        
        results.push(...virusTotalResults, ...safeBrowsingResults);
    } catch (error) {
        console.error('API check error:', error);
        results.push({
            type: 'warning',
            icon: '⚠️',
            text: 'Some security checks could not be completed',
            weight: -5
        });
    }
    
    return results;
}

async function performSSLAnalysis(url, isHttp = false) {
    console.log('Starting SSL analysis for:', url);
    
    if (typeof securityAPI === 'undefined') {
        return basicSSLCheck(url, isHttp);
    }
    
    try {
        const sslResults = await securityAPI.checkSSLLabs(url);
        console.log('SSL Labs results:', sslResults);
        return sslResults;
    } catch (error) {
        console.error('SSL analysis error:', error);
        return basicSSLCheck(url, isHttp);
    }
}

function basicSSLCheck(url, isHttp = false) {
    const results = [];
    
    if (!isHttp && url.startsWith('https://')) {
        results.push({
            type: 'good',
            icon: '🔒',
            text: 'HTTPS connection detected - SSL certificate present',
            weight: 10
        });
    } else if (!isHttp && !url.startsWith('https://')) {
        results.push({
            type: 'danger',
            icon: '🔓',
            text: 'No HTTPS - Connection is not encrypted',
            weight: -20
        });
    }
    
    return results;
}

// Helper Functions
function isLegitimateService(domain, keyword) {
    const legitimateMap = {
        'paypal': ['paypal.com'],
        'amazon': ['amazon.com', 'amazon.co.uk', 'amazon.de', 'amazon.ca'],
        'apple': ['apple.com', 'icloud.com'],
        'microsoft': ['microsoft.com', 'outlook.com', 'live.com'],
        'google': ['google.com', 'gmail.com', 'youtube.com'],
        'facebook': ['facebook.com', 'fb.com'],
        'instagram': ['instagram.com'],
        'twitter': ['twitter.com', 'x.com']
    };
    
    return legitimateMap[keyword]?.some(legitDomain => domain.includes(legitDomain)) || false;
}

function isSimilarDomain(domain1, domain2) {
    if (Math.abs(domain1.length - domain2.length) > 3) return false;
    
    let differences = 0;
    const maxLen = Math.max(domain1.length, domain2.length);
    
    for (let i = 0; i < maxLen; i++) {
        if (domain1[i] !== domain2[i]) differences++;
    }
    
    return differences <= 2 && differences > 0;
}

function calculateSecurityScore(allResults) {
    let score = 60; // Adjusted base score
    
    allResults.forEach(result => {
        score += result.weight || 0;
    });
    
    return Math.max(0, Math.min(100, score));
}

function getScoreColor(score) {
    if (score >= 70) return '#28a745';
    if (score >= 40) return '#ffc107';
    return '#dc3545';
}

function getSafetyLevel(score) {
    if (score >= 70) return { 
        level: 'safe', 
        icon: '✅', 
        title: 'Safe to Visit', 
        description: 'This URL appears to be safe based on comprehensive security analysis.' 
    };
    if (score >= 40) return { 
        level: 'warning', 
        icon: '⚠️', 
        title: 'Proceed with Caution', 
        description: 'This URL has some concerning characteristics. Be careful if you visit.' 
    };
    return { 
        level: 'danger', 
        icon: '🚨', 
        title: 'High Risk - Avoid', 
        description: 'This URL shows multiple red flags and should be avoided.' 
    };
}

// Animation Functions
async function updateProgressStep(stepIndex) {
    console.log('Updating progress step:', stepIndex);
    const steps = document.querySelectorAll('.step');
    
    for (let i = 0; i < stepIndex; i++) {
        steps[i].classList.remove('active');
        steps[i].classList.add('completed');
    }
    
    if (steps[stepIndex]) {
        steps[stepIndex].classList.add('active');
        steps[stepIndex].classList.remove('completed');
    }
}

function animateScore(targetScore, scoreElement, scoreCircle) {
    let currentScore = 0;
    const increment = targetScore / 50;
    
    const animation = setInterval(() => {
        currentScore += increment;
        if (currentScore >= targetScore) {
            currentScore = targetScore;
            clearInterval(animation);
        }
        
        scoreElement.textContent = Math.round(currentScore);
        
        const color = getScoreColor(currentScore);
        scoreCircle.style.background = `conic-gradient(from 0deg, ${color} 0%, ${color} ${currentScore}%, #e9ecef ${currentScore}%, #e9ecef 100%)`;
    }, 50);
}

// Main Analysis Function
async function checkSingleURL(url, resultContainer) {
    console.log('Starting analysis for:', url);
    
    try {
        currentStep = 0;
        const allResults = [];
        let originalUrl = url; // Store original for shortener check
        
        // Step 1: Redirect Check
        await updateProgressStep(0);
        console.log('Step 1: Checking redirects...');
        const redirectResults = await securityAPI.checkRedirects(url);
        allResults.push(...redirectResults);
        console.log('Redirect results:', redirectResults);
        
        const redirectResult = redirectResults.find(r => r.text.includes('Redirected to'));
        if (redirectResult) {
            url = redirectResult.text.split(': ')[1];
            console.log('Using final URL for further checks:', url);
        }
        
        // Check for shortener on original URL
        const shorteners = [
            'bit.ly', 't.co', 'tinyurl.com', 'goo.gl', 'ow.ly', 'short.link',
            'tiny.cc', 'is.gd', 'buff.ly', 'ift.tt', 'rb.gy'
        ];
        const originalDomain = extractDomain(originalUrl);
        if (shorteners.some(shortener => originalDomain.includes(shortener))) {
            allResults.push({
                type: 'warning',
                icon: '🔗',
                text: 'URL shortener detected - destination unknown',
                weight: -12
            });
        }
        
        // Step 2: URL Structure Analysis
        await updateProgressStep(1);
        console.log('Step 2: Analyzing URL structure...');
        await sleep(1000);
        
        const isHttp = redirectResults.some(r => r.text === 'Final URL uses unsecured HTTP');
        const structureResults = analyzeURLStructure(url, isHttp);
        const phishingResults = analyzePhishingPatterns(url);
        allResults.push(...structureResults, ...phishingResults);
        console.log('Structure and phishing results:', allResults);
        
        // Step 3: API Security Checks
        await updateProgressStep(2);
        console.log('Step 3: Performing real API security checks...');
        const apiResults = await performRealAPIChecks(url);
        allResults.push(...apiResults);
        console.log('API results:', apiResults);
        
        // Step 4: SSL Analysis
        await updateProgressStep(3);
        console.log('Step 4: Analyzing SSL certificate...');
        const sslResults = await performSSLAnalysis(url, isHttp);
        allResults.push(...sslResults);
        console.log('SSL results:', sslResults);
        
        // Step 5: Final Report
        await updateProgressStep(4);
        console.log('Step 5: Generating final report...');
        await sleep(800);
        
        const securityScore = calculateSecurityScore(allResults);
        const safetyInfo = getSafetyLevel(securityScore);
        
        console.log('Analysis complete. Score:', securityScore);
        console.log('All results:', allResults);
        
        return { url, results: allResults, score: securityScore, safetyInfo };
    } catch (error) {
        console.error('Analysis error for', url, ':', error);
        return {
            url,
            results: [{
                type: 'warning',
                icon: '⚠️',
                text: `Analysis failed: ${error.message}`,
                weight: 0
            }],
            score: 0,
            safetyInfo: {
                level: 'warning',
                icon: '⚠️',
                title: 'Analysis Failed',
                description: 'An error occurred during analysis.'
            }
        };
    }
}

async function checkURL() {
    const input = document.getElementById('urlInput');
    const bulkInput = document.getElementById('bulkUrlInput');
    const loading = document.getElementById('loading');
    const result = document.getElementById('result');
    const bulkResults = document.getElementById('bulkResults');
    const singleResult = document.querySelector('.single-result');
    const checkBtn = document.getElementById('checkBtn');
    const mode = document.querySelector('input[name="mode"]:checked').value;
    
    checkBtn.disabled = true;
    checkBtn.innerHTML = '<span class="btn-text">Analyzing...</span><span class="btn-icon">⏳</span>';
    result.style.display = 'none';
    loading.style.display = 'block';
    bulkResults.innerHTML = '';
    singleResult.style.display = 'none';
    
    try {
        if (mode === 'single') {
            const url = input.value.trim();
            console.log('Input URL:', url);
            
            if (!url) {
                console.log('No URL entered');
                alert('Please enter a URL to check');
                return;
            }
            
            if (!isValidURL(url)) {
                console.log('Invalid URL entered');
                alert('Please enter a valid URL (include http:// or https://)');
                return;
            }
            
            const analysisResult = await checkSingleURL(url);
            loading.style.display = 'none';
            singleResult.style.display = 'block';
            displayResults(analysisResult.url, analysisResult.results, analysisResult.score, analysisResult.safetyInfo);
        } else {
            const urls = bulkInput.value.trim().split('\n').map(url => url.trim()).filter(url => url && isValidURL(url));
            console.log('Bulk URLs:', urls);
            
            if (urls.length === 0) {
                console.log('No valid URLs entered');
                alert('Please enter at least one valid URL');
                return;
            }
            
            const allAnalysisResults = [];
            for (const url of urls) {
                console.log('Processing URL:', url);
                const analysisResult = await checkSingleURL(url);
                allAnalysisResults.push(analysisResult);
                await sleep(1000); // Delay to avoid API rate limits
            }
            
            loading.style.display = 'none';
            displayBulkResults(allAnalysisResults);
        }
    } catch (error) {
        console.error('Bulk analysis error:', error);
        alert('An error occurred during analysis: ' + error.message);
    } finally {
        checkBtn.disabled = false;
        checkBtn.innerHTML = '<span class="btn-text">Analyze URL(s)</span><span class="btn-icon">🔍</span>';
    }
}

function displayResults(url, results, score, safetyInfo) {
    const resultIcon = document.getElementById('resultIcon');
    const resultTitle = document.getElementById('resultTitle');
    const resultDescription = document.getElementById('resultDescription');
    const resultDetails = document.getElementById('resultDetails');
    const resultHeader = document.querySelector('.result-header');
    
    resultIcon.textContent = safetyInfo.icon;
    resultTitle.textContent = safetyInfo.title;
    resultDescription.textContent = safetyInfo.description;
    
    resultHeader.className = `result-header ${safetyInfo.level}`;
    
    resultDetails.innerHTML = results.map(result => `
        <div class="detail-item ${result.type}">
            <div class="detail-icon">${result.icon}</div>
            <div class="detail-text">${result.text}</div>
        </div>
    `).join('');
    
    const urlInfo = document.createElement('div');
    urlInfo.className = 'url-info';
    urlInfo.innerHTML = `
        <div style="background: #f8f9fa; padding: 15px; border-radius: 8px; margin-bottom: 20px;">
            <strong>Analyzed URL:</strong> <code style="background: white; padding: 2px 6px; border-radius: 4px;">${url}</code>
        </div>
    `;
    resultDetails.insertBefore(urlInfo, resultDetails.firstChild);
    
    const scoreElement = document.getElementById('scoreNumber');
    const scoreCircle = document.querySelector('.score-circle');
    animateScore(score, scoreElement, scoreCircle);
    
    document.getElementById('result').style.display = 'block';
    document.getElementById('result').scrollIntoView({ behavior: 'smooth' });
}

function displayBulkResults(analysisResults) {
    const bulkResults = document.getElementById('bulkResults');
    bulkResults.innerHTML = analysisResults.map((result, index) => `
        <div class="bulk-result-item">
            <h3>URL ${index + 1}: <code>${result.url}</code></h3>
            <div class="result-header ${result.safetyInfo.level}">
                <span class="result-icon">${result.safetyInfo.icon}</span>
                <div class="result-info">
                    <h2>${result.safetyInfo.title}</h2>
                    <p>${result.safetyInfo.description}</p>
                </div>
            </div>
            <div class="security-score">
                <div class="score-circle" id="scoreCircle${index}">
                    <span class="score-number" id="scoreNumber${index}">${result.score}</span>
                    <span class="score-label">Security Score</span>
                </div>
            </div>
            <div class="result-details">
                ${result.results.map(r => `
                    <div class="detail-item ${r.type}">
                        <div class="detail-icon">${r.icon}</div>
                        <div class="detail-text">${r.text}</div>
                    </div>
                `).join('')}
            </div>
        </div>
    `).join('');
    
    analysisResults.forEach((result, index) => {
        const scoreElement = document.getElementById(`scoreNumber${index}`);
        const scoreCircle = document.getElementById(`scoreCircle${index}`);
        animateScore(result.score, scoreElement, scoreCircle);
    });
    
    document.getElementById('result').style.display = 'block';
    document.getElementById('result').scrollIntoView({ behavior: 'smooth' });
}

// Event Listeners
document.getElementById('urlInput').addEventListener('keypress', function(e) {
    if (e.key === 'Enter') {
        console.log('Enter key pressed, triggering checkURL');
        checkURL();
    }
});

document.getElementById('checkBtn').addEventListener('click', function() {
    console.log('Analyze URL button clicked, triggering checkURL');
    checkURL();
});

document.getElementById('urlInput').addEventListener('paste', function(e) {
    setTimeout(() => {
        const pastedUrl = e.target.value;
        if (pastedUrl && isValidURL(pastedUrl)) {
            console.log('Valid URL pasted:', pastedUrl);
        }
    }, 100);
});

// Toggle between single and bulk input
document.querySelectorAll('input[name="mode"]').forEach(radio => {
    radio.addEventListener('change', function() {
        const urlInput = document.getElementById('urlInput');
        const bulkUrlInput = document.getElementById('bulkUrlInput');
        if (this.value === 'single') {
            urlInput.style.display = 'block';
            bulkUrlInput.style.display = 'none';
        } else {
            urlInput.style.display = 'none';
            bulkUrlInput.style.display = 'block';
        }
    });
});

// Initialize
document.addEventListener('DOMContentLoaded', function() {
    console.log('SafeLink URL Security Checker with Real API Integration initialized');
    
    if (typeof securityAPI !== 'undefined') {
        console.log('✅ API handler loaded successfully');
    } else {
        console.warn('⚠️ API handler not found - make sure api-handler.js is loaded');
    }
    
    if (typeof API_CONFIG !== 'undefined') {
        console.log('✅ API configuration loaded');
        if (API_CONFIG.DEMO_MODE) {
            console.log('📝 Demo mode is enabled - switch to real API keys in config.js');
        }
    } else {
        console.warn('⚠️ API configuration not found - make sure config.js is loaded');
    }
});
