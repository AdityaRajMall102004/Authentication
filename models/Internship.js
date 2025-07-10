// // models/Internship.js

// const mongoose = require('mongoose');

// // Define the schema for an Internship post
// const InternshipSchema = new mongoose.Schema({
//     company: {
//         type: String,
//         required: true,
//         trim: true
//     },
//     batch: {
//         type: String,
//         required: true,
//         trim: true
//     },
//     link: {
//         type: String,
//         required: true,
//         trim: true,
//         match: [/^https?:\/\/[^\s$.?#].[^\s]*$/, 'Please use a valid URL for the link']
//     },
//     postedBy: {
//         type: mongoose.Schema.Types.ObjectId,
//         ref: 'User', // References the 'User' model
//         required: true
//     }
// }, {
//     timestamps: true // Automatically adds createdAt and updatedAt fields
// });

// // Export the Mongoose model
// module.exports = mongoose.model('Internship', InternshipSchema);


const mongoose = require('mongoose');

const internshipSchema = new mongoose.Schema({
    company: { type: String, required: true },
    batch: { type: String, required: true },
    description: { type: String, required: true },
    link: { type: String, required: true }, // Keep if you want to show the URL
    deadline: { type: Date, required: true }, // <--- ADD THIS LINE
    postedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Internship', internshipSchema);