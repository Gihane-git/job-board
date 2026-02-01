

// backend/server.js
// -------------------- DEPENDENCIES -------------------- //
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cheerio = require('cheerio');
const Parser = require('rss-parser');
const parser = new Parser();
const { htmlToText } = require('html-to-text');
require('dotenv').config();
const path = require('path');
const multer = require('multer');
const fs = require('fs');
const chalk = require('chalk');
const axios = require('axios');
const schedule = require('node-schedule');
const he = require('he');

// -------------------- LOAD ENV VARIABLES -------------------- //
require('dotenv').config(); // Load .env into process.env

// -------------------- MYSQL CONNECTION (WITH PROMISES) -------------------- //

const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
}).promise();

console.log('✅ MySQL connection configured (promise-based)');


// For node-fetch v3 in CommonJS
const fetch = (...args) => import('node-fetch').then(({ default: fetch }) => fetch(...args));

// -------------------- INIT -------------------- //
const app = express();
const PORT = 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'your_secret_here';

// -------------------- MIDDLEWARE -------------------- //
app.use(cors());
app.use(bodyParser.json());


// -------------------- SLACK ALERT -------------------- //
const SLACK_WEBHOOK_URL = process.env.SLACK_WEBHOOK_URL;
async function sendSlackAlert(message) {
  if (!SLACK_WEBHOOK_URL) return;
  try {
    await axios.post(SLACK_WEBHOOK_URL, { text: message });
  } catch (err) {
    console.error(chalk.red('❌ Failed to send Slack alert:'), err.message);
  }
}

// -------------------- DAILY JOB CLEANUP -------------------- //
async function dailyJobCleanup() {
  try {
    console.log('🧹 Running daily job cleanup...');
    const [result] = await db.query(`DELETE FROM jobs WHERE created_at < NOW() - INTERVAL 40 DAY`);
    console.log(`✅ Daily cleanup done. Removed ${result.affectedRows} jobs.`);
  } catch (err) {
    console.error('❌ Daily cleanup failed:', err);
    await sendSlackAlert(`❌ Daily cleanup failed: ${err.message}`);
  }
}
// Run every day at midnight
schedule.scheduleJob('0 0 * * *', dailyJobCleanup);

// -------------------- UPLOADS -------------------- //
const resumeDir = path.join(__dirname, 'uploads/resumes');
const avatarDir = path.join(__dirname, 'uploads/avatars');
if (!fs.existsSync(resumeDir)) fs.mkdirSync(resumeDir, { recursive: true });
if (!fs.existsSync(avatarDir)) fs.mkdirSync(avatarDir, { recursive: true });

const resumeStorage = multer.diskStorage({
  destination: resumeDir,
  filename: (req, file, cb) => cb(null, `resume-${Date.now()}${path.extname(file.originalname)}`)
});
const uploadResume = multer({ storage: resumeStorage });

const avatarStorage = multer.diskStorage({
  destination: avatarDir,
  filename: (req, file, cb) => cb(null, `avatar-${Date.now()}${path.extname(file.originalname)}`)
});
const avatarFileFilter = (req, file, cb) => {
  const allowedTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
  if (allowedTypes.includes(file.mimetype)) cb(null, true);
  else { cb(null, false); req.fileValidationError = 'Only image files are allowed!'; }
};
const uploadAvatar = multer({ storage: avatarStorage, fileFilter: avatarFileFilter });
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// -------------------- AUTH MIDDLEWARE -------------------- //
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token missing.' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token.' });
    req.user = user;
    next();
  });
}

// -------------------- SAFE FETCH -------------------- //
async function safeFetchJSON(url, label, options = {}) {
  try {
    const res = await fetch(url, options);
    const text = await res.text();
    try {
      return JSON.parse(text);
    } catch (err) {
      console.error(`❌ [${label}] Failed to parse JSON:`, err.message);
      console.error(`🔍 Body: ${text.slice(0, 200)}...`);
      return null;
    }
  } catch (err) {
    console.error(`❌ [${label}] Fetch failed:`, err.message);
    return null;
  }
}

// -------------------- GREENHOUSE COMPANIES -------------------- //
const greenhouseCompanies = [
  { name: 'Stripe', slug: 'stripe' },
  { name: 'Coinbase', slug: 'coinbase' },
  { name: 'Notion', slug: 'notion' },
  { name: 'Shopify', slug: 'shopify' },
  { name: 'Vercel', slug: 'vercel' },
  { name: 'Dropbox', slug: 'dropbox' },
  { name: 'Airbnb', slug: 'airbnb' },
  { name: 'Figma', slug: 'figma' },
  { name: 'Asana', slug: 'asana' }
];

// -------------------- BATCH INSERT HELPER -------------------- //
async function batchInsertJobs(jobs, batchSize = 100) {
  if (!jobs.length) return 0;

  const insertQuery = `
    INSERT IGNORE INTO jobs
    (title, company, location, description, url, source, created_at, greenhouse_id)
    VALUES ?
  `;
  let totalInserted = 0;
  for (let i = 0; i < jobs.length; i += batchSize) {
    const batch = jobs.slice(i, i + batchSize);
    const values = batch.map(j => [
      j.title,
      j.company,
      j.location,
      j.description,
      j.url || '',
      j.source,
      new Date(),
      j.greenhouse_id || null
    ]);
    const [result] = await db.query(insertQuery, [values]);
    totalInserted += result.affectedRows;
    console.log(`📦 Batch ${i / batchSize + 1}: inserted ${result.affectedRows}`);
  }
  return totalInserted;
}




function stripHtml(html) {
  if (!html) return '';
  const $ = cheerio.load(html);
  return $.text().replace(/\s+/g, ' ').trim();
}


// -------------------- IMPORT ALL JOBS -------------------- //
app.get('/import/all-jobs', async (req, res) => {
  try {
    let allJobs = [];
    let totalSources = 0;

    // -------------------- GREENHOUSE -------------------- //
  

for (const company of greenhouseCompanies) {
  totalSources++;
  console.log(`🔎 Fetching ${company.name} (Greenhouse)`);

  const data = await safeFetchJSON(
    `https://boards-api.greenhouse.io/v1/boards/${company.slug}/jobs`,
    `Greenhouse-${company.name}`
  );
  if (!data?.jobs?.length) continue;

  const jobs = await Promise.all(
    data.jobs.slice(0, 5).map(async job => {
      let description = job.content?.trim();

      if (!description) {
        const detailData = await safeFetchJSON(
          `https://boards-api.greenhouse.io/v1/boards/${company.slug}/jobs/${job.id}`,
          `Greenhouse-Job-${job.id}`
        );
        description = detailData?.content?.trim();
      }

      if (!description) return null;

      // 1️⃣ Decode HTML entities
      description = he.decode(description);

      // 2️⃣ Strip HTML tags and collapse whitespace
      description = description.replace(/<\/?[^>]+(>|$)/g, " ").replace(/\s+/g, " ").trim();

      return {
        title: job.title || 'No title',
        company: company.name,
        location: job.location?.name || 'Remote',
        description, // clean plain text
        url: `https://boards.greenhouse.io/${company.slug}/jobs/${job.id}`,
        source: 'greenhouse',
        greenhouse_id: job.id
      };
    })
  );

  allJobs.push(...jobs.filter(Boolean));
  console.log(`✅ ${company.name}: ${jobs.filter(Boolean).length} jobs fetched`);
}

    
    

    // -------------------- EXTERNAL SOURCES -------------------- //
    const sources = [];

    // 1️⃣ RemoteOK API
    const remoteOkJson = await safeFetchJSON('https://remoteok.com/api', 'RemoteOK');
    if (Array.isArray(remoteOkJson)) {
      const jobsArray = remoteOkJson.slice(1); // skip metadata
      sources.push({
        name: 'remoteok',
        jobs: jobsArray
          .filter(j => j.position || j.title)
          .map(j => ({
            title: j.position || j.title,
            company: j.company || 'Unknown',
            location: j.location || 'Remote',
            description: j.description ? htmlToText(j.description, { wordwrap: 130 }) : '',
            url: j.url || '',
            source: 'remoteok'
          }))
      });
      totalSources++;
    }

    // 2️⃣ Remotive API
    try {
      const remRes = await fetch('https://remotive.com/api/remote-jobs?limit=50');
      const remJobs = (await remRes.json()).jobs || [];
      sources.push({
        name: 'remotive',
        jobs: remJobs.map(j => ({
          title: j.title,
          company: j.company_name || 'Unknown',
          location: j.candidate_required_location || 'Remote',
          description: j.description ? htmlToText(j.description, { wordwrap: 130 }) : '',
          url: j.url || '',
          source: 'remotive'
        }))
      });
      totalSources++;
    } catch (err) {
      console.error('[Remotive] Fetch failed:', err.message);
    }

    // 3️⃣ We Work Remotely RSS
    try {
      const wwrFeed = await parser.parseURL('https://weworkremotely.com/categories/remote-programming-jobs.rss');
      const wwrJobs = wwrFeed.items.map(item => {
        const $ = cheerio.load(item.content || '');
        $('img, script, style, iframe, a').remove();
        return {
          title: item.title || 'No title',
          company: item.creator || item.author || 'Unknown',
          location: 'Remote',
          description: $.root().text().replace(/\s+/g, ' ').trim() || '',
          url: item.link || '',
          source: 'weworkremotely'
        };
      });
      sources.push({ name: 'weworkremotely', jobs: wwrJobs });
      totalSources++;
    } catch (err) {
      console.error('[WeWorkRemotely] RSS fetch failed:', err.message);
    }

    // 4️⃣ Jobicy RSS
    try {
      const jobicyFeed = await parser.parseURL('https://jobicy.com/?feed=job_feed');
      const jobs = jobicyFeed.items.map(item => ({
        title: item.title || 'No title',
        company: item.creator || item['dc:creator'] || 'Unknown',
        location: item['job:location'] || 'Remote',
        description: htmlToText(item['content:encoded'] || item.content || '', { wordwrap: 130 }),
        url: item.link || '',
        source: 'jobicy_rss'
      }));
      sources.push({ name: 'jobicy_rss', jobs });
      totalSources++;
    } catch (err) {
      console.error('[Jobicy RSS] Fetch failed:', err.message);
    }

    // 5️⃣ Jobicy API
    try {
      const jobicyJson = await safeFetchJSON('https://jobicy.com/api/v2/remote-jobs', 'Jobicy');
      if (jobicyJson?.jobs && Array.isArray(jobicyJson.jobs)) {
        const jobs = jobicyJson.jobs.map(j => ({
          title: j.jobTitle || 'No title',
          company: j.companyName || 'Unknown',
          location: j.jobGeo || 'Remote',
          description: j.jobDescription || '',
          url: j.url || '',
          source: 'jobicy_api'
        }));
        sources.push({ name: 'jobicy_api', jobs });
        totalSources++;
      }
    } catch (err) {
      console.error('[Jobicy API] Fetch failed:', err.message);
    }

    // 6️⃣ Himalayas RSS
    try {
      const hmFeed = await parser.parseURL('https://himalayas.app/jobs/rss');
      const hmJobs = hmFeed.items.map(item => ({
        title: item.title || 'No title',
        company: item['himalayasJobs:companyName'] || item.creator || 'Unknown',
        location: item['himalayasJobs:locationRestriction'] || 'Remote',
        description: htmlToText(item.content || '', { wordwrap: 130 }),
        url: item.link || '',
        source: 'himalayas'
      }));
      sources.push({ name: 'himalayas', jobs: hmJobs });
      totalSources++;
    } catch (err) {
      console.error('[Himalayas] Fetch failed:', err.message);
    }

    // 7️⃣ Empllo RSS
    try {
      const emplloFeed = await parser.parseURL('https://empllo.com/feeds/remote-jobs.rss');
      const emplloJobs = emplloFeed.items.map(item => ({
        title: item.title || 'No title',
        company: item.creator || 'Unknown',
        location: 'Remote',
        description: htmlToText(item.content || '', { wordwrap: 130 }),
        url: item.link || '',
        source: 'empllo'
      }));
      sources.push({ name: 'empllo', jobs: emplloJobs });
      totalSources++;
    } catch (err) {
      console.error('[Empllo] Fetch failed:', err.message);
    }

    // 8️⃣ HireWeb3 RSS
    try {
      const hireFeed = await parser.parseURL('https://hireweb3.io/job/rss');
      const hireJobs = hireFeed.items.map(item => ({
        title: item.title || 'No title',
        company: item['hireweb3Jobs:companyName'] || item.creator || 'Unknown',
        location: item['hireweb3Jobs:location'] || 'Remote',
        description: htmlToText(item.content || '', { wordwrap: 130 }),
        url: item.link || '',
        source: 'hireweb3'
      }));
      sources.push({ name: 'hireweb3', jobs: hireJobs });
      totalSources++;
    } catch (err) {
      console.error('[HireWeb3] Fetch failed:', err.message);
    }

   // -------------------- ADD EXTERNAL JOBS TO ALL -------------------- //
for (const src of sources) {
  const validJobs = src.jobs.filter(j => j.title && j.company);
  allJobs.push(...validJobs);
  console.log(`✅ Source "${src.name}" returned ${validJobs.length} jobs`);
}


    // -------------------- INSERT INTO DB -------------------- //
    const totalInserted = await batchInsertJobs(allJobs);

    res.json({
      success: true,
      totalSources,
      totalJobsFetched: allJobs.length,
      totalInserted
    });
    console.log(`✅ All imports done: ${totalInserted} new jobs from ${totalSources} sources`);
  } catch (err) {
    console.error('❌ Import all jobs error:', err);
    res.status(500).json({ error: 'Failed to import all jobs' });
  }
});


// -------------------- JOBS ROUTES -------------------- //
app.get('/jobs', async (req, res) => {
  const page = Math.max(1, parseInt(req.query.page, 10) || 1);
  const pageSize = Math.max(1, parseInt(req.query.pageSize, 10) || 5);
  const offset = (page - 1) * pageSize;
  const searchRaw = req.query.search || '';
  const search = searchRaw ? `%${searchRaw.toLowerCase()}%` : null;

  if (!Number.isInteger(page) || !Number.isInteger(pageSize) || pageSize > 50 || offset < 0) {
    return res.status(400).json({ error: 'Invalid pagination parameters' });
  }

  try {
    let query = `
      SELECT id, title, company, location, description, user_id, source, created_at
      FROM jobs
    `;
    const params = [];

    // 🔍 SEARCH MODE → NO PAGINATION
    if (search) {
      query += `
        WHERE LOWER(title) LIKE ?
           OR LOWER(company) LIKE ?
           OR LOWER(description) LIKE ?
        ORDER BY created_at DESC
      `;
      params.push(search, search, search);
    } 
    // 📄 NORMAL MODE → PAGINATED
    else {
      query += `
        ORDER BY created_at DESC
        LIMIT ${pageSize} OFFSET ${offset}
      `;
    }

    const [jobs] = await db.query(query, params);

    // 🔢 TOTAL COUNT
    const [[{ total }]] = await db.query(
      search
        ? `
          SELECT COUNT(*) AS total 
          FROM jobs 
          WHERE LOWER(title) LIKE ? 
             OR LOWER(company) LIKE ? 
             OR LOWER(description) LIKE ?
        `
        : `SELECT COUNT(*) AS total FROM jobs`,
      search ? [search, search, search] : []
    );

    res.json({
      jobs,
      totalJobs: total,
      currentPage: search ? 1 : page,
      totalPages: search ? 1 : Math.ceil(total / pageSize),
    });
  } catch (err) {
    console.error('❌ Error fetching jobs:', err);
    res.status(500).json({ error: 'Database error' });
  }
});







app.get('/jobs/:id', async (req, res) => {
  const { id } = req.params;

  if (isNaN(id)) {
    return res.status(400).json({ error: 'Invalid job ID.' });
  }

  try {
    const [rows] = await db.execute(
      'SELECT * FROM jobs WHERE id = ?',
      [id]
    );

    if (rows.length === 0) {
      return res.status(404).json({ error: 'Job not found.' });
    }

    const job = rows[0];

    // ✅ Guarantee description for frontend
    job.description =
      job.description && job.description.trim()
        ? job.description
        : 'No description available';

    res.json(job);
  } catch (err) {
    console.error('❌ Error fetching job:', err);
    res.status(500).json({ error: 'Database error' });
  }
});



// save a job
app.post('/jobs/:id/save', authenticateToken, async (req, res) => {
  try {
    await db.execute(
      'INSERT IGNORE INTO saved_jobs (user_id, job_id) VALUES (?, ?)',
      [req.user.id, req.params.id]
    );
    res.status(201).json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to save job' });
  }
});

// get saved jobs
app.get('/my-saved-jobs', authenticateToken, async (req, res) => {
  try {
    const [rows] = await db.execute(
      `
      SELECT 
        j.id,
        j.title,
        j.company,
        j.location,
        j.description,
        j.source
      FROM jobs j
      JOIN saved_jobs s ON s.job_id = j.id
      WHERE s.user_id = ?
      `,
      [req.user.id]
    );

    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch saved jobs' });
  }
});


// remove saved job
app.delete('/jobs/:id/save', authenticateToken, async (req, res) => {
  try {
    const [result] = await db.execute(
      'DELETE FROM saved_jobs WHERE user_id = ? AND job_id = ?',
      [req.user.id, req.params.id]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Saved job not found' });
    }

    res.json({ success: true });
  } catch (err) {
    console.error('❌ Failed to remove saved job:', err);
    res.status(500).json({ error: 'Failed to remove saved job' });
  }
});

//Apply to a job
app.post('/jobs/:id/apply', authenticateToken, async (req, res) => {
  try {
    await db.execute(
      'INSERT IGNORE INTO applied_jobs (user_id, job_id) VALUES (?, ?)',
      [req.user.id, req.params.id]
    );
    res.status(201).json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to apply' });
  }
});

//Get applied jobs
app.get('/my-applied-jobs', authenticateToken, async (req, res) => {
  try {
    const [rows] = await db.execute(`
      SELECT j.*
      FROM jobs j
      JOIN applied_jobs a ON a.job_id = j.id
      WHERE a.user_id = ?
    `, [req.user.id]);

    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch applied jobs' });
  }
});



app.post('/jobs', authenticateToken, async (req, res) => {
  const { title, company, location, description } = req.body;
  const userId = req.user.id;

  if (!title || title.length < 2 || !company || company.length < 2 || !location || !description || description.length < 10) {
    return res.status(400).json({ error: 'Invalid job input.' });
  }

  try {
    const [result] = await db.execute(
      'INSERT INTO jobs (title, company, location, description, source, user_id) VALUES (?, ?, ?, ?, ?, ?)',
      [title, company, location, description, 'user', userId]
    );

    res.status(201).json({
      id: result.insertId,
      title,
      company,
      location,
      description,
      source: 'user',
      user_id: userId,
    });
  } catch (err) {
    console.error('Error inserting job:', err);
    res.status(500).json({ error: 'Database error.' });
  }
});

app.put('/jobs/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { title, company, location, description } = req.body;
  const userId = req.user.id;

  if (!title || title.length < 2 || !company || company.length < 2 || !location || !description || description.length < 10) {
    return res.status(400).json({ error: 'Invalid job input.' });
  }

  try {
    const [result] = await db.execute(
      'UPDATE jobs SET title = ?, company = ?, location = ?, description = ? WHERE id = ? AND user_id = ?',
      [title, company, location, description, id, userId]
    );

    if (result.affectedRows === 0) {
      return res.status(403).json({ error: 'Unauthorized or job not found.' });
    }

    res.json({ success: true, updatedJob: { id, title, company, location, description } });
  } catch (err) {
    console.error('Error updating job:', err);
    res.status(500).json({ error: 'Database error.' });
  }
});

app.delete('/jobs/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const userId = req.user.id;

  if (isNaN(id)) return res.status(400).json({ error: 'Invalid job ID.' });

  try {
    const [result] = await db.execute(
      'DELETE FROM jobs WHERE id = ? AND user_id = ?',
      [id, userId]
    );

    if (result.affectedRows === 0) 
      return res.status(404).json({ error: 'Job not found or unauthorized.' });

    res.json({ success: true });
  } catch (err) {
    console.error('Error deleting job:', err);
    res.status(500).json({ error: 'Database error.' });
  }
});


// -------------------- AUTH ROUTES -------------------- //
app.post('/register', async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password) return res.status(400).json({ error: 'All fields are required.' });

  try {
    const hashed = await bcrypt.hash(password, 10);
    const [result] = await db.execute(
      'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
      [username, email, hashed]
    );

    res.status(201).json({ id: result.insertId, username, email });
  } catch (err) {
    console.error('Registration DB error:', err);
    res.status(500).json({ error: 'Database error.' });
  }
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password are required.' });

  try {
    const [rows] = await db.execute('SELECT * FROM users WHERE email = ?', [email]);
    if (rows.length === 0) return res.status(401).json({ error: 'Invalid credentials.' });

    const user = rows[0];
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials.' });

    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Something went wrong.' });
  }
});

app.get('/users/:id', authenticateToken, async (req, res) => {
  const userIdParam = parseInt(req.params.id, 10);
  if (userIdParam !== req.user.id) return res.status(403).json({ error: 'Unauthorized' });

  try {
    const [rows] = await db.execute(
      'SELECT id, username, email, name, skills, resumeUrl, avatarUrl FROM users WHERE id = ?',
  [userIdParam]
    );
    if (rows.length === 0) return res.status(404).json({ error: 'User not found' });
    res.json(rows[0]);
  } catch (err) {
    console.error('Error fetching user profile:', err);
    res.status(500).json({ error: 'Failed to load profile' });
  }
});

app.put('/users/:id', authenticateToken, async (req, res) => {
  const userId = parseInt(req.params.id, 10);

  if (userId !== req.user.id) return res.status(403).json({ error: 'Unauthorized' });

  try {
    const { name, skills, resumeUrl, avatarUrl, email, password } = req.body;
    let hashedPassword = null;

    if (password) {
      hashedPassword = await bcrypt.hash(password, 10);
    }

    await db.execute(
      `
      UPDATE users
      SET
        name = COALESCE(?, name),
        email = COALESCE(?, email),
        skills = COALESCE(?, skills),
        resumeUrl = COALESCE(?, resumeUrl),
        avatarUrl = COALESCE(?, avatarUrl),
        password = COALESCE(?, password)
      WHERE id = ?
      `,
      [
        name ?? null,
        email ?? null,
        skills ? JSON.stringify(skills) : null,
        resumeUrl ?? null,
        avatarUrl ?? null,
        hashedPassword,
        userId,
      ]
    );
    
  
    res.status(200).json({ message: 'Profile updated successfully' });
  } catch (err) {
    console.error('Failed to update user:', err);
    res.status(500).json({ error: 'Failed to update profile' });
  }
  
  
});


app.get('/my-jobs', authenticateToken, async (req, res) => {
  const userId = req.user.id;

  try {
    const [jobs] = await db.execute('SELECT * FROM jobs WHERE user_id = ?', [userId]);
    res.json(jobs);
  } catch (err) {
    console.error('Error fetching user jobs:', err);
    res.status(500).json({ error: 'Database error' });
  }
});

app.post(
  '/upload-resume',authenticateToken,uploadResume.single('resume'),async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

  const resumePath = `/uploads/resumes/${req.file.filename}`;
  try {
    // Optionally: update user’s resumeUrl
    await db.execute('UPDATE users SET resumeUrl = ? WHERE id = ?', [resumePath, req.user.id]);
    res.status(200).json({ resumeUrl: resumePath });
  } catch (err) {
    console.error('❌ Error saving resume URL to DB:', err);
    res.status(500).json({ error: 'Failed to save resume URL' });
  }
});

app.post(
  '/upload/avatar',
  authenticateToken,
  uploadAvatar.single('avatar'),
  async (req, res) => {
    // Check for file validation error
    if (req.fileValidationError) {
      return res.status(400).json({ error: req.fileValidationError });
    }

    // Check if file is uploaded
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const avatarPath = `/uploads/avatars/${req.file.filename}`;

    try {
      await db.execute('UPDATE users SET avatarUrl = ? WHERE id = ?', [avatarPath, req.user.id]);

      res.status(200).json({
        success: true,
        url: `${req.protocol}://${req.get('host')}${avatarPath}`,
      });
    } catch (err) {
      console.error('❌ Error saving avatar URL to DB:', err);
      res.status(500).json({ error: 'Failed to save avatar URL' });
    }
  }
);


// -------------------- TEST ROUTE -------------------- //
app.get('/', (req, res) => res.send('Job Board API running'));

// -------------------- START SERVER -------------------- //
app.listen(PORT, () => {
  console.log(`🚀 Server is running at http://localhost:${PORT}`);
});
