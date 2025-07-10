const mongoose = require('mongoose');
const bcrypt = require('bcrypt'); // Still needed for hashing passwords

const UserSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true,
        unique: true, // Ensures no two users can have the same username/email
        lowercase: true, // Store emails in lowercase for consistency
        trim: true,
        match: [/^[^\s@]+@[^\s@]+\.[^\s@]+$/, 'Please use a valid email address'] // Basic email validation
    },
    password: {
        type: String,
        required: true
    },
    otpToken: { // Changed from otp_token to camelCase for Mongoose convention
        type: String,
        default: null
    },
    otpExpires: { // Changed from otp_expires to camelCase
        type: Number, // Store as Unix timestamp (milliseconds)
        default: null
    },
    allowReset: { // Changed from allow_reset to camelCase
        type: Boolean,
        default: false
    }
}, { timestamps: true }); // Mongoose adds `createdAt` and `updatedAt` fields automatically

// Pre-save hook to hash password before saving a new user or updating password
UserSchema.pre('save', async function(next) {
    // Only hash the password if it has been modified (or is new)
    if (!this.isModified('password')) {
        return next();
    }
    try {
        const salt = await bcrypt.genSalt(10);
        this.password = await bcrypt.hash(this.password, salt);
        next();
    } catch (err) {
        next(err);
    }
});

// Method to compare password (for login)
UserSchema.methods.comparePassword = async function(candidatePassword) {
    return await bcrypt.compare(candidatePassword, this.password);
};

module.exports = mongoose.model('User', UserSchema);