import express from 'express';
   import cors from 'cors';
   import fetch from 'node-fetch';
   import path from 'path';
   import { fileURLToPath } from 'url';

   const __filename = fileURLToPath(import.meta.url);
   const __dirname = path.dirname(__filename);

   const app = express();
   const PORT = 3000;

   // Enable CORS and JSON parsing
   app.use(cors());
   app.use(express.json());
   app.use(express.static('.'));

   // Serve your HTML files
   app.get('/', (req, res) => {
       res.sendFile(path.join(__dirname, 'index.html'));
   });

   // VirusTotal API proxy
   app.post('/api/virustotal/scan', async (req, res) => {
       try {
           const { url, apiKey } = req.body;
           
           const response = await fetch('https://www.virustotal.com/vtapi/v2/url/scan', {
               method: 'POST',
               headers: {
                   'Content-Type': 'application/x-www-form-urlencoded',
               },
               body: `apikey=${apiKey}&url=${encodeURIComponent(url)}`
           });
           
           const data = await response.json();
           res.json(data);
       } catch (error) {
           console.error('VirusTotal scan error:', error);
           res.status(500).json({ error: 'VirusTotal scan failed' });
       }
   });

   app.get('/api/virustotal/report', async (req, res) => {
       try {
           const { url, apiKey } = req.query;
           
           const response = await fetch(
               `https://www.virustotal.com/vtapi/v2/url/report?apikey=${apiKey}&resource=${encodeURIComponent(url)}`
           );
           
           const data = await response.json();
           res.json(data);
       } catch (error) {
           console.error('VirusTotal report error:', error);
           res.status(500).json({ error: 'VirusTotal report failed' });
       }
   });

   // Google Safe Browsing API proxy
   app.post('/api/safebrowsing', async (req, res) => {
       try {
           const { url, apiKey } = req.body;
           
           const requestBody = {
               client: {
                   clientId: "safelink-checker",
                   clientVersion: "1.0.0"
               },
               threatInfo: {
                   threatTypes: [
                       "MALWARE",
                       "SOCIAL_ENGINEERING", 
                       "UNWANTED_SOFTWARE",
                       "POTENTIALLY_HARMFUL_APPLICATION"
                   ],
                   platformTypes: ["ANY_PLATFORM"],
                   threatEntryTypes: ["URL"],
                   threatEntries: [{ url: url }]
               }
           };

           const response = await fetch(
               `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`,
               {
                   method: 'POST',
                   headers: {
                       'Content-Type': 'application/json',
                   },
                   body: JSON.stringify(requestBody)
               }
           );

           const data = await response.json();
           res.json(data);
       } catch (error) {
           console.error('Safe Browsing error:', error);
           res.status(500).json({ error: 'Safe Browsing check failed' });
       }
   });

   // SSL Labs API proxy
   app.get('/api/ssllabs', async (req, res) => {
       try {
           const { host, startNew } = req.query;
           let url = `https://api.ssllabs.com/api/v3/analyze?host=${host}&all=done`;
           
           if (startNew === 'true') {
               url += '&startNew=on';
           }
           
           const response = await fetch(url);
           const data = await response.json();
           res.json(data);
       } catch (error) {
           console.error('SSL Labs error:', error);
           res.status(500).json({ error: 'SSL Labs check failed' });
       }
   });

   // Redirect tracking endpoint
   app.get('/api/redirects', async (req, res) => {
       try {
           const { url } = req.query;
           if (!url) {
               return res.status(400).json({ error: 'URL parameter is required' });
           }

           const response = await fetch(url, {
               method: 'GET',
               redirect: 'follow',
               headers: {
                   'User-Agent': 'SafeLink/1.0.0'
               }
           });

           res.json({
               originalUrl: url,
               finalUrl: response.url,
               status: response.status,
               statusText: response.statusText
           });
       } catch (error) {
           console.error('Redirect tracking error:', error);
           res.status(500).json({ error: 'Failed to track redirects' });
       }
   });

   app.listen(PORT, () => {
       console.log(`🚀 SafeLink server running on http://localhost:${PORT}`);
       console.log('📝 Open your browser and go to http://localhost:3000');
   });