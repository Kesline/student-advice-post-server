const mongoose = require('mongoose');

const questionSchema = new mongoose.Schema({
  question: String
});

module.exports = mongoose.model('Question', questionSchema);
