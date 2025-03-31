const passport = require('passport');
const nodemailer = require('nodemailer');
const { google } = require("googleapis");
const jwt = require('jsonwebtoken');
require('dotenv').config();

const User = require('../models/User');

const {
    GOOGLE_CLIENT_ID,
    GOOGLE_CLIENT_SECRET,
    GOOGLE_CLIENT_TOKEN,
    JWT_RESET_KEY,
    GMAIL_USER,
} = process.env;

// Fonction pour configurer OAuth2 et obtenir un access token
const getAccessToken = async () => {
    console.log("[INFO] Obtention du token d'accès OAuth2...");
    const oauth2Client = new google.auth.OAuth2(
        GOOGLE_CLIENT_ID,
        GOOGLE_CLIENT_SECRET,
        "https://developers.google.com/oauthplayground"
    );
    oauth2Client.setCredentials({ refresh_token: GOOGLE_CLIENT_TOKEN });
    const accessToken = await oauth2Client.getAccessToken();
    console.log("[SUCCESS] Token d'accès obtenu.");
    return accessToken;
};

// Fonction pour envoyer un email
const sendResetEmail = async (email, token) => {
    console.log(`[INFO] Préparation de l'envoi de l'email à ${email}...`);
    const accessToken = await getAccessToken();

    const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            type: "OAuth2",
            user: GMAIL_USER,
            clientId: GOOGLE_CLIENT_ID,
            clientSecret: GOOGLE_CLIENT_SECRET,
            refreshToken: GOOGLE_CLIENT_TOKEN,
            accessToken
        },
    });

    const CLIENT_URL = `http://${process.env.HOST || 'localhost'}`;
    const mailOptions = {
        from: `"Auth Admin" <${GMAIL_USER}>`,
        to: email,
        subject: "Password Reset Request",
        html: `
            <h2>Click the link below to reset your password</h2>
            <p>${CLIENT_URL}/auth/forgot/${token}</p>
            <p><b>NOTE:</b> This link expires in 30 minutes.</p>
        `,
    };

    await transporter.sendMail(mailOptions);
    console.log(`[SUCCESS] Email envoyé à ${email}.`);
    console.log(`TOKEN RESET: ${CLIENT_URL}/auth/forgot/${token}`);
};

// Route Forgot Password
exports.forgotPassword = async (req, res) => {
    const { email } = req.body;
    console.log("[INFO] Demande de réinitialisation du mot de passe reçue.");

    if (!email) {
        console.log("[ERROR] Email non fourni.");
        return res.render('forgot', { errors: [{ msg: 'Please enter an email' }], email });
    }

    try {
        console.log(`[INFO] Recherche de l'utilisateur avec l'email: ${email}...`);
        const user = await User.findOne({ email });

        if (!user) {
            console.log("[ERROR] Utilisateur non trouvé.");
            return res.render('forgot', { errors: [{ msg: 'User not found' }], email });
        }

        console.log("[SUCCESS] Utilisateur trouvé, génération du token JWT...");
        const token = jwt.sign({ _id: user._id }, JWT_RESET_KEY, { expiresIn: '30m' });

        console.log("[INFO] Mise à jour de la base de données avec le token de réinitialisation...");
        await User.updateOne({ _id: user._id }, { resetLink: token });
        console.log("[SUCCESS] Token de réinitialisation mis à jour dans la base de données.");

        await sendResetEmail(email, token);

        console.log("[INFO] Redirection vers la page de connexion après envoi de l'email.");
        req.flash('success_msg', 'Password reset link sent. Check your email.');
        res.redirect('/auth/login');
    } catch (err) {
        console.error("[ERROR] Une erreur est survenue:", err);
        req.flash('error_msg', 'An error occurred. Please try again.');
        res.redirect('/auth/forgot');
    }
};
