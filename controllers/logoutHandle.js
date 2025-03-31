const passport = require('passport');
const bcryptjs = require('bcryptjs');
const nodemailer = require('nodemailer');
const { google } = require("googleapis");
const OAuth2 = google.auth.OAuth2;
const jwt = require('jsonwebtoken');
require('dotenv').config();  // Charge les variables d'environnement

//------------ User Model ------------//
const User = require('../models/User');

//------------ Environment Variables ------------//
const { 
    GOOGLE_CLIENT_ID,
    GOOGLE_CLIENT_SECRET,
    GOOGLE_CLIENT_TOKEN,
    JWT_KEY,
    JWT_RESET_KEY,
    GMAIL_USER,
} = process.env;  // Charge les variables d'environnement

//------------ Vérification de mot de passe avec caractères spéciaux ------------//
function isValidPassword(password) {
    const regex = /^(?=.*[\W_]).{8,}$/; // Au moins 8 caractères et un caractère spécial
    return regex.test(password);
}




//------------ Logout Handle ------------//
exports.logoutHandle = (req, res) => {
    req.logout();
    req.flash('success_msg', 'You are logged out');
    res.redirect('/auth/login');
}