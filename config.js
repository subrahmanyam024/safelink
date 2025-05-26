const API_CONFIG = {
    VIRUSTOTAL: {
        key: 'your_real_virustotal_key_here',//virustotal api key
        url: 'https://www.virustotal.com/vtapi/v2/url'
    },
    SAFE_BROWSING: {
        key: 'your_real_safe_browsing_key_here',//gemini api key
        url: 'https://safebrowsing.googleapis.com/v4/threatMatches:find'
    },
    SSL_LABS: {
        url: 'https://api.ssllabs.com/api/v3/analyze'
    }
};
const DEMO_MODE = false; // Set to true if no real keys