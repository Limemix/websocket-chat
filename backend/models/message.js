const mongoose = require('mongoose');

const messageSchema = new mongoose.Schema({
    chatRoom: {type: mongoose.Schema.Types.ObjectId, ref: 'Group'},
    username: { type: String},
    message: { type: String },
    audio: { type: Buffer },  
    timestamp: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Message', messageSchema);
