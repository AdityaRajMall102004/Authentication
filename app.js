const express = require('express');
const fs = require('fs').promises; 
const path = require('path');
const bodyParser = require('body-parser');
const cron = require('node-cron');//for session of deleting post
const bcrypt = require('bcrypt');
const session = require('express-session');
const MongoStore = require('connect-mongo'); 
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const Internship = require('./models/Internship'); 
const methodOverride = require('method-override');
require('dotenv').config();

const connectDB = require('./database'); // Path to your database.js
const User = require('./models/User');   // Path to your User.js model
const app = express();
const PORT = process.env.PORT || 3000; // Use environment variable for port
const LOGIN_LOG_FILE = path.join(__dirname, 'login_log.txt'); // Keep for local logs

// --- Connect to MongoDB ---
connectDB();

// Middleware
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json()); // Add this for parsing JSON request bodies too, if needed

// --- Configure session store for MongoDB Atlas ---
app.use(methodOverride('_method')); // <--- ADD THIS LINE. It looks for '_method' in query string or body.

// --- Configure session store for MongoDB Atlas ---
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
        mongoUrl: process.env.MONGODB_URI,
        collectionName: 'sessions',
        ttl: 14 * 24 * 60 * 60,
        autoRemove: 'interval',
        autoRemoveInterval: 10
    }),
    cookie: {
        maxAge: 24 * 60 * 60 * 1000,
        secure: process.env.NODE_ENV === 'production'
    }
}));
app.use(express.static(path.join(__dirname, 'public')));


// --- Authentication Middleware ---
async function isAuthenticated(req, res, next) {
    if (req.session.userId) { // Check if userId is present in session
        try {
            // Find user by ID stored in session. Select only necessary fields.
            const user = await User.findById(req.session.userId).select('username');
            if (user) {
                req.user = {
                    id: user._id, // Mongoose documents have _id as the primary key
                    username: user.username
                };
                next(); // User is authenticated, proceed
            } else {
                // User ID in session doesn't match a valid user in DB
                req.session.destroy(() => { // Destroy session to log them out
                    res.redirect('/login');
                });
            }
        } catch (error) {
            console.error('Error in isAuthenticated middleware:', error);
            req.session.destroy(() => {
                res.redirect('/login');
            });
        }
    } else {
        res.redirect('/login'); // Not authenticated, redirect to login
    }
}


cron.schedule('0 * * * *', async () => {
    const now = new Date();
    console.log(`[Cron Job] Running daily check for expired internships at ${now.toLocaleString()}`);

    try {
        // Find internships where the deadline is less than or equal to the current time
        const result = await Internship.deleteMany({
            deadline: { $lte: now }
        });

        if (result.deletedCount > 0) {
            console.log(`[Cron Job] Deleted ${result.deletedCount} expired internships.`);
        } else {
            console.log(`[Cron Job] No expired internships found to delete.`);
        }
    } catch (error) {
        console.error('[Cron Job Error] Failed to delete expired internships:', error);
    }
});



// --- Routes ---

app.get('/', (req, res) => res.redirect('/login'));

app.get('/signup', (req, res) => {
    res.render('signup', { error1: null, error2: null });
});

app.post('/signup', async (req, res) => {
    const { username, password } = req.body;
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

    if (!emailRegex.test(username)) {
      return res.render('signup', { error1: 'Invalid email format', error2: null });
    }
    
    if (password.length < 6) {
        return res.render('signup', { error1: null, error2: 'Password must be at least 6 characters long' });
    }

    try {
        // Mongoose pre-save hook on User model handles hashing automatically
        const newUser = new User({ username, password });
        await newUser.save(); // This will trigger the pre('save') hook for hashing

        const now = new Date();
        const logEntry = `${username} Signed up 1st time at ${now.toLocaleString()}\n`;
        await fs.appendFile(LOGIN_LOG_FILE, logEntry);

        req.session.username = newUser.username;
        req.session.userId = newUser._id; // Store MongoDB's _id in session

        res.redirect('/dashboard');

    } catch (error) {
        console.error('Error during signup:', error);
        // MongoDB duplicate key error code is 11000
        if (error.code === 11000) {
            return res.render('signup', { error1: 'Email already exists.', error2: null });
        }
        res.status(500).render('signup', { error1: 'Server error during signup.', error2: null });
    }
});

app.get('/login', (req, res) => {
     res.render('login', { error3: null, error4: null });
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        const user = await User.findOne({ username }); // Find user by username/email

        if (!user) {
            return res.render('login', { error3: 'Invalid Email', error4: null });
        }

        const match = await user.comparePassword(password); // Use the instance method defined in model
        if (!match) {
            return res.render('login', { error3: null, error4: 'Wrong password' });
        }

        req.session.username = user.username;
        req.session.userId = user._id; // Store MongoDB's _id in session

        const now = new Date();
        const logEntry = `${username} logged in at ${now.toLocaleString()}\n`;
        await fs.appendFile(LOGIN_LOG_FILE, logEntry);

        res.redirect('/dashboard');

    } catch (error) {
        console.error('Error during login:', error);
        res.status(500).render('login', { error3: 'Server error during login', error4: null });
    }
});


app.get('/dashboard', isAuthenticated, async (req, res) => {
    try {
        // Fetch all internship posts, sorted by newest first (createdAt: -1)
        // Limit to 20 most recent posts. Adjust this number as needed.
        // Populate 'postedBy' to get the 'username' from the User model
        const internships = await Internship.find({})
                                            .sort({ createdAt: -1 })
                                            .limit(20)
                                            .populate('postedBy', 'username');

        // Pass the username from req.user and the fetched internships to the dashboard template
        // Also check if there's a 'message' query parameter (e.g., from a successful post redirect)
        const successMessage = req.query.message || null;
        const errorMessage = req.query.error || null; // In case you want to redirect with error

        res.render('dashboard', {
            username: req.user.username, // Using 'username' as expected by dashboard.ejs
            internships: internships,
            message: successMessage,
            error: errorMessage
        });
    } catch (error) {
        console.error('Error fetching internships for dashboard:', error);
        // On error, still render dashboard but with an empty internship list and an error message
        res.status(500).render('dashboard', {
            username: req.user.username,
            internships: [],
            message: null,
            error: 'Failed to load internships. Please try again.'
        });
    }
});

app.post('/logout', (req, res) => { // Modified for session destruction
    req.session.destroy((err) => {
        if (err) {
            console.error('Error destroying session:', err);
            return res.status(500).send('Could not log out.');
        }
        res.redirect('/login');
    });
});


app.get('/forgot', (req, res) => {
    res.render('forgot', { error: null, message: null });
});

app.post('/forgot', async (req, res) => {
    const { username } = req.body;

    try {
        const user = await User.findOne({ username });

        if (!user) {
            return res.render('forgot', { error: 'Email not found', message: null });
        }

        // Generate OTP
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const expiry = Date.now() + 5 * 60 * 1000; // valid for 5 minutes

        // Update user in MongoDB
        await User.updateOne(
            { _id: user._id }, // Find by user ID
            { otpToken: otp, otpExpires: expiry, allowReset: false }
        );

        // Send OTP via Gmail
        const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: process.env.GMAIL_USER, // Use env variable
                pass: process.env.GMAIL_PASS  // Use env variable (App Password)
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
    } catch (error) {
        console.error('Error during forgot password request:', error);
        res.status(500).render('forgot', { error: 'Server error. Try again.', message: null });
    }
});

app.post('/verify', async (req, res) => {
    const { username, otp } = req.body;

    try {
        const user = await User.findOne({ username });

        if (!user || user.otpToken !== otp || user.otpExpires < Date.now()) {
            return res.render('verify', { username, error: 'Invalid or expired OTP' });
        }

        // Update user in MongoDB
        await User.updateOne(
            { _id: user._id },
            { allowReset: true, otpToken: null, otpExpires: null } // Clear OTP fields
        );

        res.render('reset', { username, error: null, message: null });
    } catch (error) {
        console.error('Error during OTP verification:', error);
        res.status(500).render('verify', { username, error: 'Server error during verification.' });
    }
});

app.post('/reset', async (req, res) => {
    const { username, password, confirmPassword } = req.body;

    try {
        const user = await User.findOne({ username });

        if (!user || !user.allowReset) {
            return res.render('reset', { username, error: 'Session expired or unauthorized. Please request OTP again.', message: null });
        }

        if (password !== confirmPassword) {
            return res.render('reset', { username, error: 'Passwords do not match.', message: null });
        }

        if (password.length < 6) {
            return res.render('reset', { username, error: 'Password must be at least 6 characters.', message: null });
        }

        // Assign new password to the Mongoose user object.
        // The pre('save') hook in the User model will automatically hash this.
        user.password = password;
        user.allowReset = false; // Reset the flag
        await user.save(); // Save the updated user document

        res.render('reset', { username: null, error: null, message: '✅ Password successfully changed! You can now log in.' });
    } catch (error) {
        console.error('Error during password reset:', error);
        res.status(500).render('reset', { username, error: 'Server error during password reset.', message: null });
    }
});


// app.js (Add these new routes, for example, after your /reset POST route)

// --- NEW ROUTE: Display the simplified form to post an internship ---
app.get('/post-internship', isAuthenticated, (req, res) => {
    res.render('post-internship', { error: null });
});

// --- NEW ROUTE: Handle simplified internship post submission ---
// app.post('/post-internship', isAuthenticated, async (req, res) => {
//     const { company, batch, link } = req.body;
//     const postedBy = req.user.id;

//     if (!company || !batch || !link) {
//         return res.render('post-internship', { error: 'Company, Batch, and Link are all required fields.' });
//     }

//     try {
//         const newInternship = new Internship({
//             company: company.trim(),
//             batch: batch.trim(),
//             link: link.trim(),
//             postedBy: postedBy
//         });

//         await newInternship.save();
//         // Redirect back to dashboard with a success message
//         res.redirect('/dashboard?message=Internship link posted successfully!');
//     } catch (error) {
//         console.error('Error posting internship link:', error);
//         let errorMessage = 'Failed to post internship link. Please try again.';
//         if (error.name === 'ValidationError') { // Mongoose validation error
//             errorMessage = error.message;
//         }
//         res.status(500).render('post-internship', { error: errorMessage });
//     }
// });


// Assuming you have this route already
app.post('/post-internship', isAuthenticated, async (req, res) => {
    try {
        const { company, batch, description, link, deadline } = req.body; // <--- ADD 'deadline' here

        // Basic validation for deadline
        if (!deadline || new Date(deadline) < new Date()) {
            return res.redirect('/post-internship?error=Deadline cannot be in the past or empty.');
        }

        const newInternship = new Internship({
            company,
            batch,
            description,
            link,
            deadline: new Date(deadline), // <--- Save deadline as a Date object
            postedBy: req.session.userId
        });
        await newInternship.save();
        res.redirect('/dashboard?message=Internship posted successfully!');
    } catch (error) {
        console.error('Error posting internship:', error);
        res.redirect('/post-internship?error=Failed to post internship.');
    }
});
// --- NEW ROUTE: View a Single Internship Post in Detail ---
// app.js (Corrected /internship/:id GET route)

app.get('/internship/:id', isAuthenticated, async (req, res) => {
    try {
        const internship = await Internship.findById(req.params.id)
                                             .populate('postedBy', 'username');

        if (!internship) {
            return res.status(404).render('error', { message: 'Internship link not found.' });
        }
        res.render('internship-detail', {
            internship: internship,
            username: req.user.username, // Still pass username for general display
            user: req.user // <-- CRUCIAL FIX: Pass the entire req.user object for ID comparison
        });
    } catch (error) {
        console.error('Error fetching internship link detail:', error);
        res.status(500).render('error', { message: 'Server error fetching internship link details.' });
    }
});



// --- NEW ROUTE: Handle Internship Deletion (DELETE) ---
app.delete('/internship/:id', isAuthenticated, async (req, res) => {
    try {
        const internshipId = req.params.id;
        const loggedInUserId = req.user.id; // From isAuthenticated middleware

        // 1. Find the internship
        const internship = await Internship.findById(internshipId);

        // 2. Check if internship exists
        if (!internship) {
            console.log(`Attempted to delete non-existent internship: ${internshipId}`);
            return res.status(404).redirect('/dashboard?error=Internship not found.');
        }

        // 3. Authorization Check: Ensure the logged-in user is the poster of the internship
        // Mongoose ObjectIds need to be converted to strings for proper comparison
        if (internship.postedBy.toString() !== loggedInUserId.toString()) {
            console.log(`Unauthorized deletion attempt by user ${loggedInUserId} on post ${internshipId}`);
            return res.status(403).redirect('/dashboard?error=You are not authorized to delete this post.');
        }

        // 4. Delete the internship
        await Internship.findByIdAndDelete(internshipId);
        console.log(`Internship ${internshipId} deleted by user ${loggedInUserId}.`);

        // Redirect back to dashboard with a success message
        res.redirect('/dashboard?message=Internship post deleted successfully!');

    } catch (error) {
        console.error('Error during internship deletion:', error);
        // If the ID format is invalid, findByIdAndDelete might throw an error
        let errorMessage = 'Server error during deletion. Please try again.';
        if (error.name === 'CastError') { // Mongoose CastError for invalid ObjectId format
            errorMessage = 'Invalid internship ID format.';
        }
        res.status(500).redirect(`/dashboard?error=${encodeURIComponent(errorMessage)}`);
    }
});

// ... rest of your app.js file (e.g., app.listen)

app.listen(PORT, () => {
    console.log(`✅ Server running at http://localhost:${PORT}`);
    console.log(`Connected to MongoDB: ${process.env.MONGODB_URI ? process.env.MONGODB_URI.split('@')[1].split('/')[0] : 'Not Connected'}`);
});