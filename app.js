const express = require('express');
const fs = require('fs').promises;
const path = require('path');
const bodyParser = require('body-parser');

const bcrypt = require('bcrypt');
const session = require('express-session');
const crypto = require('crypto');
const nodemailer = require('nodemailer');

const app = express();
const PORT = 3000;

const USERS_FILE = path.join(__dirname, 'users.json');
const LOGIN_LOG_FILE = path.join(__dirname, 'login_log.txt');

// Middleware
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(bodyParser.urlencoded({ extended: true }));

app.use(session({
    secret: 'mysecretkey',
    resave: false,
    saveUninitialized: false
}));

//This line tells your Express app to serve static files (like HTML, CSS, JS, images).
app.use(express.static(path.join(__dirname, 'public')));

// Utility: Read or initialize users file

//await--await is a keyword used inside an async function to pause the execution of the function
// until a Promise is settled (either resolved or rejected).
async function readUsersFile() {
    try {       //'utf8' means it reads the file as a text string, not a buffer.
        const data = await fs.readFile(USERS_FILE, 'utf8');
        return JSON.parse(data);//converts JSON string(data)into a JS object(likely an array of users).
    } catch (err) {
        return [];
    }
}

async function writeUsersFile(users) {
// | Parameter  | Value   | Purpose                                   |
// | ---------- | ------- | ----------------------------------------- |
// | `value`    | `users` | The data to convert to JSON               |
// | `replacer` | `null`  | Don't filter any properties               |
// | `space`    | `2`     | Indent JSON with 2 spaces for readability |

    await fs.writeFile(USERS_FILE, JSON.stringify(users, null, 2));
}

// Routes
app.get('/', (req, res) => res.redirect('/login'));

app.get('/signup', (req, res) => {
    res.render('signup', { error1: null, error2: null });
});

app.post('/signup', async (req, res) => {
    const { username, password } = req.body;
    const users = await readUsersFile();
    const exists = users.find(user => user.username === username);
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(username)) {
      return res.render('signup', { error1: 'Invalid email format', error2: null });
    }
    if (exists) {
        return res.render('signup', { error1: 'Email already exists', error2: null });
    }
    
    if (password.length < 6) {
        return res.render('signup', { error1: null, error2: 'Password must be at least 6 characters long' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    users.push({ username, password: hashedPassword });
    await writeUsersFile(users);

    const now = new Date();
    const logEntry = `${username} Signed in 1st time at ${now.toLocaleString()}\n`;
    await fs.appendFile(LOGIN_LOG_FILE, logEntry);

    res.redirect('/dashboard');
});

app.get('/login', (req, res) => {
     res.render('login', { error3: null, error4: null });
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const users = await readUsersFile();

    const user = users.find(users => users.username === username);
    if (!user) {
        return res.render('login', { error3: 'Invalid Email', error4: null });
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
        return res.render('login', { error3: null, error4: 'Wrong password' });
    }

    req.session.username = username;

    const now = new Date();
    const logEntry = `${username} logged in at ${now.toLocaleString()}\n`;
    await fs.appendFile(LOGIN_LOG_FILE, logEntry);

    res.redirect('/dashboard');
});

app.get('/dashboard', (req, res) => {
    res.render('dashboard', { user_name: req.session.username });
});

app.post('/logout', async (req, res) => {
    res.redirect('/login');
});


app.get('/forgot', (req, res) => {
    res.render('forgot', { error: null, message: null });
});




app.post('/forgot', async (req, res) => {
    const { username } = req.body;
    const users = await readUsersFile();
    const user = users.find(u => u.username === username);

    if (!user) {
        return res.render('forgot', { error: 'Email not found', message: null });
    }

    // Generate OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiry = Date.now() + 5 * 60 * 1000; // valid for 5 minutes

    user.otpToken = otp;
    user.otpExpires = expiry;
    await writeUsersFile(users);

    // Send OTP via Gmail
    const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: 'ad2421853@gmail.com',
            pass: 'vuuodhjoafstybey'
        }
    });

    transporter.sendMail({
        from: '"StudyCloud" <ad2421853@gmail.com>',
        to: user.username,
        subject: 'Your OTP to Reset Password',
        html: `<h3>Your OTP: <b>${otp}</b></h3><p>It is valid for 5 minutes.</p>`
    }, (err, info) => {
        if (err) {
            console.error('❌ Email error:', err);
            return res.render('forgot', { error: 'Failed to send OTP. Try again.', message: null });
        } else {
            console.log('✅ Email sent:', info.response);
            return res.render('verify', { username: user.username, error: null });
        }
    });
});
app.post('/verify', async (req, res) => {
    const { username, otp } = req.body;
    const users = await readUsersFile();
    const user = users.find(u => u.username === username);

    if (!user || user.otpToken !== otp || user.otpExpires < Date.now()) {
        return res.render('verify', { username, error: 'Invalid or expired OTP' });
    }

    user.allowReset = true;
    delete user.otpToken;
    delete user.otpExpires;
    await writeUsersFile(users);

    res.render('reset', { username, error: null, message: null });
});


app.post('/reset', async (req, res) => {
    const { username, password, confirmPassword } = req.body;
    const users = await readUsersFile();
    const user = users.find(u => u.username === username);

    if (!user || !user.allowReset) {
        return res.render('reset', { username, error: 'Session expired or unauthorized.', message: null });
    }

    if (password !== confirmPassword) {
        return res.render('reset', { username, error: 'Passwords do not match.', message: null });
    }

    if (password.length < 6) {
        return res.render('reset', { username, error: 'Password must be at least 6 characters.', message: null });
    }

    user.password = await bcrypt.hash(password, 10);
    delete user.allowReset;
    await writeUsersFile(users);

    res.render('reset', { username: null, error: null, message: '✅ Password successfully changed!' });
});



app.listen(PORT, () => {
    console.log(`✅ Server running at http://localhost:${PORT}`);
});

