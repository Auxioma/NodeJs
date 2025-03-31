const mongoose = require('mongoose');
const validator = require('validator');

//------------ User Schema ------------//
const UserSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, 'le nom est obligatoire'],
    trim: true, 
    maxlength: [50, 'votre nom peut contenir 50 caractere'],
    minlength: [2, 'votre nom est trop court']
  },
  email: {
    type: String,
    required: [true, 'le mail est obligatoire'],
    unique: true,
    lowercase: true,
    trim: true, 
    validate: [validator.isEmail, 'merci de fournir un mail valise']
  },
  password: {
    type: String,
    required: [true, 'Le mot de passe est obligatoire'],
    minlength: [8, 'le ndp dois faire > 8 caractere']
  },
  verified: {
    type: Boolean,
    default: false
  },
  resetLink: {
    type: String,
    default: ''
  }
}, { timestamps: true });

const User = mongoose.model('User', UserSchema);

module.exports = User;