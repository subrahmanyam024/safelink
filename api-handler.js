
class SecurityAPIHandler {
    constructor() {
        this.serverUrl = 'http://localhost:3000';
    }

    async checkRedirects(url) {
        try {
            console.log('Checking redirects for:', url);
            const response = await fetch(`${this.serverUrl}/api/redirects?url=${encodeURIComponent(url)}`);
            const data = await response.json();

            if (data.error) {
                console.error('Redirect check error:', data.error);
                return [{
                    type: 'warning',
                    icon: '⚠️',
                    text: 'Unable to track redirects',
                    weight: 0
                }];
            }

            console.log('Redirect results:', data);
            const results = [];

            if (data.originalUrl === data.finalUrl) {
                results.push({
                    type: 'good',
                    icon: '✅',
                    text: 'No redirects detected',
                    weight: 5
                });
            } else {
                results.push({
                    type: 'info',
                    icon: '🔗',
                    text: `Redirected to: ${data.finalUrl}`,
                    weight: 0
                });

                if (!data.finalUrl.startsWith('https://')) {
                    results.push({
                        type: 'warning',
                        icon: '⚠️',
                        text: 'Final URL uses unsecured HTTP',
                        weight: -5
                    });
                }
            }

            return results;
        } catch (error) {
            console.error('Redirect check error:', error);
            return [{
                type: 'warning',
                icon: '⚠️',
                text: 'Redirect tracking temporarily unavailable',
                weight: 0
            }];
        }
    }

    async checkVirusTotal(url) {
        try {
            console.log('Checking VirusTotal for:', url);
            
            const submitResponse = await fetch(`${this.serverUrl}/api/virustotal/scan`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    url: url,
                    apiKey: API_CONFIG.VIRUSTOTAL.key
                })
            });

            const submitData = await submitResponse.json();
            console.log('VirusTotal submit response:', submitData);

            await this.sleep(2000);

            const reportResponse = await fetch(
                `${this.serverUrl}/api/virustotal/report?url=${encodeURIComponent(url)}&apiKey=${API_CONFIG.VIRUSTOTAL.key}`
            );

            const reportData = await reportResponse.json();
            console.log('VirusTotal report:', reportData);

            return this.parseVirusTotalResults(reportData);
        } catch (error) {
            console.error('VirusTotal API error:', error);
            return [{
                type: 'warning',
                icon: '⚠️',
                text: 'VirusTotal scan temporarily unavailable',
                weight: 0
            }];
        }
    }

    async checkSafeBrowsing(url) {
        try {
            console.log('Checking Google Safe Browsing for:', url);

            const response = await fetch(`${this.serverUrl}/api/safebrowsing`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    url: url,
                    apiKey: API_CONFIG.SAFE_BROWSING.key
                })
            });

            const data = await response.json();
            console.log('Safe Browsing response:', data);

            return this.parseSafeBrowsingResults(data);
        } catch (error) {
            console.error('Safe Browsing API error:', error);
            return [{
                type: 'warning',
                icon: '⚠️',
                text: 'Google Safe Browsing check unavailable',
                weight: 0
            }];
        }
    }

    async checkSSLLabs(url) {
        try {
            const hostname = new URL(url).hostname;
            console.log('Checking SSL Labs for:', hostname);

            const startResponse = await fetch(
                `${this.serverUrl}/api/ssllabs?host=${hostname}&startNew=true`
            );

            let data = await startResponse.json();
            console.log('SSL Labs initial response:', data);

            let attempts = 0;
            while (data.status === 'IN_PROGRESS' && attempts < 6) {
                await this.sleep(5000);
                const pollResponse = await fetch(
                    `${this.serverUrl}/api/ssllabs?host=${hostname}`
                );
                data = await pollResponse.json();
                attempts++;
                console.log(`SSL Labs poll attempt ${attempts}:`, data.status);
            }

            return this.parseSSLLabsResults(data, url);
        } catch (error) {
            console.error('SSL Labs API error:', error);
            return this.fallbackSSLCheck(url);
        }
    }

    parseVirusTotalResults(data) {
        const results = [];

        if (data.response_code === 1) {
            const positives = data.positives || 0;
            const total = data.total || 0;

            if (positives === 0) {
                results.push({
                    type: 'good',
                    icon: '🛡️',
                    text: `Clean - 0/${total} security vendors flagged this URL`,
                    weight: 25
                });
            } else if (positives <= 2) {
                results.push({
                    type: 'warning',
                    icon: '⚠️',
                    text: `Low risk - ${positives}/${total} security vendors flagged this URL`,
                    weight: -10
                });
            } else {
                results.push({
                    type: 'danger',
                    icon: '🚨',
                    text: `High risk - ${positives}/${total} security vendors flagged this URL as malicious!`,
                    weight: -30
                });
            }

            if (data.scan_date) {
                results.push({
                    type: 'good',
                    icon: '📅',
                    text: `Last scanned: ${new Date(data.scan_date).toLocaleDateString()}`,
                    weight: 5
                });
            }
        } else if (data.response_code === 0) {
            results.push({
                type: 'warning',
                icon: '🔍',
                text: 'URL not found in VirusTotal database - first time scan',
                weight: -5
            });
        }

        return results;
    }

    parseSafeBrowsingResults(data) {
        const results = [];

        if (!data.matches || data.matches.length === 0) {
            results.push({
                type: 'good',
                icon: '✅',
                text: 'Google Safe Browsing: No threats detected',
                weight: 20
            });
        } else {
            data.matches.forEach(match => {
                const threatType = match.threatType;
                let threatDescription = '';
                let weight = -25;

                switch (threatType) {
                    case 'MALWARE':
                        threatDescription = 'Contains malware';
                        weight = -30;
                        break;
                    case 'SOCIAL_ENGINEERING':
                        threatDescription = 'Phishing/social engineering site';
                        weight = -35;
                        break;
                    case 'UNWANTED_SOFTWARE':
                        threatDescription = 'Hosts unwanted software';
                        weight = -20;
                        break;
                    case 'POTENTIALLY_HARMFUL_APPLICATION':
                        threatDescription = 'Potentially harmful application';
                        weight = -15;
                        break;
                    default:
                        threatDescription = 'Security threat detected';
                }

                results.push({
                    type: 'danger',
                    icon: '🚨',
                    text: `Google Safe Browsing: ${threatDescription}`,
                    weight: weight
                });
            });
        }

        return results;
    }

    parseSSLLabsResults(data, url) {
        const results = [];

        if (data.status === 'READY' && data.endpoints && data.endpoints.length > 0) {
            const endpoint = data.endpoints[0];
            const grade = endpoint.grade;

            if (grade) {
                if (['A+', 'A', 'A-'].includes(grade)) {
                    results.push({
                        type: 'good',
                        icon: '🏆',
                        text: `SSL Grade: ${grade} - Excellent security`,
                        weight: 20
                    });
                } else if (['B', 'C'].includes(grade)) {
                    results.push({
                        type: 'warning',
                        icon: '⚠️',
                        text: `SSL Grade: ${grade} - Moderate security`,
                        weight: 5
                    });
                } else {
                    results.push({
                        type: 'danger',
                        icon: '❌',
                        text: `SSL Grade: ${grade} - Poor security`,
                        weight: -15
                    });
                }
            }
        } else {
            return this.fallbackSSLCheck(url);
        }

        return results;
    }

    fallbackSSLCheck(url) {
        if (url.startsWith('https://')) {
            return [{
                type: 'good',
                icon: '🔒',
                text: 'HTTPS connection detected - SSL certificate present',
                weight: 10
            }];
        } else {
            return [{
                type: 'danger',
                icon: '🔓',
                text: 'No HTTPS - Connection is not encrypted',
                weight: -20
            }];
        }
    }

    sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
}

const securityAPI = new SecurityAPIHandler();
