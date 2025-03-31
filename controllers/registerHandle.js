// Importation des modules nécessaires pour la gestion de l'authentification et des envois d'emails.
const passport = require('passport');  // Passport est utilisé pour la gestion de l'authentification.
const bcrypt = require('bcryptjs');  // bcrypt pour le hachage des mots de passe.
const nodemailer = require('nodemailer');  // Nodemailer pour l'envoi d'emails.
const { google } = require("googleapis");  // Importation des outils Google pour l'authentification OAuth2.
const jwt = require('jsonwebtoken');  // jsonwebtoken pour générer des tokens JWT (JSON Web Token).
require('dotenv').config();  // Charge les variables d'environnement depuis un fichier .env.

const User = require('../models/User');  // Importation du modèle User pour interagir avec la base de données.

const {
    GOOGLE_CLIENT_ID,
    GOOGLE_CLIENT_SECRET,
    GOOGLE_CLIENT_TOKEN,
    JWT_KEY,
    GMAIL_USER,
} = process.env;  // Récupère les variables d'environnement définies dans le fichier .env.

if (!GOOGLE_CLIENT_ID) {
    console.error("GOOGLE_CLIENT_ID is missing. Check your .env file.");
    process.exit(1);  // Si le client ID Google est manquant, le programme s'arrête pour éviter des erreurs.
}

if (!GOOGLE_CLIENT_SECRET) {
    console.error("GOOGLE_CLIENT_SECRET is missing. Check your .env file.");
    process.exit(1);  // Si le client secret Google est manquant, le programme s'arrête.
}

if (!GOOGLE_CLIENT_TOKEN) {
    console.error("GOOGLE_CLIENT_TOKEN is missing. Check your .env file.");
    process.exit(1);  // Si le token Google est manquant, le programme s'arrête.
}

// Création d'un client OAuth2 Google avec les informations nécessaires.
const oauth2Client = new google.auth.OAuth2(
    GOOGLE_CLIENT_ID,  // ID du client pour OAuth2.
    GOOGLE_CLIENT_SECRET,  // Secret du client pour OAuth2.
    "https://developers.google.com/oauthplayground"  // URL de redirection pour le processus OAuth2.
);

// Ajout du token de rafraîchissement pour obtenir un nouveau token d'accès.
oauth2Client.setCredentials({ refresh_token: GOOGLE_CLIENT_TOKEN });

async function getAccessToken() {
    try {
        console.log("Obtaining access token...");
        const { token } = await oauth2Client.getAccessToken();  // Récupère un token d'accès à Google.
        console.log("Access token obtained successfully");
        return token;  // Retourne le token d'accès.
    } catch (err) {
        console.error('Error obtaining access token:', err);  // En cas d'erreur, on l'affiche dans la console.
        return null;  // Si l'obtention du token échoue, retourne null.
    }
}

// Fonction pour valider un mot de passe avec une expression régulière.
function isValidPassword(password) {
    return /^(?=.*[!@#$%^&*(),.?":{}|<>]).{8,}$/.test(password);  // Le mot de passe doit faire 8 caractères minimum et contenir un caractère spécial.
}

// Fonction qui gère l'enregistrement de l'utilisateur.
exports.registerHandle = async (req, res) => {
    console.log("Register request received:", req.body);  // Affiche la demande d'enregistrement dans la console pour débogage.
    const { name, email, password, password2 } = req.body;  // Récupère les données envoyées dans le formulaire.
    let errors = [];  // Tableau pour stocker les erreurs de validation.

    // Vérification que tous les champs sont remplis.
    if (!name || !email || !password || !password2) {
        errors.push({ msg: 'Veuillez remplir tous les champs' });  // Si un champ est vide, ajouter une erreur.
    }

    // Vérification que les mots de passe correspondent.
    if (password !== password2) {
        errors.push({ msg: 'Les mots de passe ne correspondent pas' });  // Si les mots de passe sont différents, ajouter une erreur.
    }

    // Vérification de la validité du mot de passe.
    if (!isValidPassword(password)) {
        errors.push({ msg: 'Le mot de passe doit contenir au moins 8 caractères et un caractère spécial' });  // Ajoute une erreur si le mot de passe ne respecte pas les règles.
    }

    // Si des erreurs existent, on retourne le formulaire d'inscription avec les erreurs affichées.
    if (errors.length > 0) {
        console.log("Validation errors:", errors);  // Affiche les erreurs de validation.
        return res.render('register', { errors, name, email, password, password2 });  // Renvoie la page d'inscription avec les erreurs.
    }

    try {
        console.log("Checking if user already exists...");  // Vérifie si l'utilisateur existe déjà.
        const existingUser = await User.findOne({ email });  // Recherche un utilisateur avec le même email dans la base de données.
        if (existingUser) {
            console.log("User already exists:", email);  // Si l'utilisateur existe déjà, affiche un message.
            errors.push({ msg: 'Cet email est déjà enregistré' });  // Ajoute une erreur si l'email existe déjà.
            return res.render('register', { errors, name, email, password, password2 });  // Renvoie le formulaire d'inscription avec l'erreur.
        }

        console.log("User does not exist, proceeding with registration...");  // Si l'utilisateur n'existe pas, on continue l'inscription.
        const accessToken = await getAccessToken();  // Récupère un token d'accès Google.
        if (!accessToken) {
            console.error("Failed to obtain access token");  // Si on échoue à obtenir le token, on affiche une erreur.
            errors.push({ msg: 'Erreur de connexion avec Google' });  // Ajoute une erreur pour la connexion Google.
            return res.render('register', { errors, name, email, password, password2 });  // Renvoie le formulaire avec l'erreur.
        }

        const token = jwt.sign({ name, email, password }, JWT_KEY, { expiresIn: '30m' });  // Génère un token JWT pour l'activation du compte.
        const CLIENT_URL = `http://${req.headers.host}`;  // Récupère l'URL de l'application pour le lien de confirmation.
        console.log("Generated activation token for user:", email);  // Affiche le token généré.

        // Préparation des options pour envoyer l'email de confirmation.
        const mailOptions = {
            from: `"Auth Admin" <${GMAIL_USER}>`,  // Expéditeur de l'email.
            to: email,  // Destinataire de l'email.
            subject: "Vérification de compte ✔",  // Sujet de l'email.
            html: `<h2>Veuillez cliquer sur le lien ci-dessous pour activer votre compte</h2>
                   <p>${CLIENT_URL}/auth/activate/${token}</p>
                   <p><b>Note :</b> Ce lien expirera dans 30 minutes.</p>`  // Corps de l'email avec le lien d'activation.
        };

        console.log("Sending email to:", email);  // Affiche dans la console qu'on envoie l'email.
        console.log(`Token:  ${CLIENT_URL}/auth/activate/${token}`); // Uniquement pour avoir l'URL d'activation dans le terminal. 
        
        // Création du transporteur pour envoyer l'email avec OAuth2.
        const transporter = nodemailer.createTransport({
            service: 'gmail',  // Service Gmail pour l'envoi de l'email.
            auth: {
                type: "OAuth2",  // Utilisation de l'authentification OAuth2.
                user: GMAIL_USER,  // Utilisateur Gmail.
                clientId: GOOGLE_CLIENT_ID,  // ID du client Google.
                clientSecret: GOOGLE_CLIENT_SECRET,  // Secret du client Google.
                refreshToken: GOOGLE_CLIENT_TOKEN,  // Token de rafraîchissement pour obtenir un nouveau token d'accès.
                accessToken: accessToken,  // Token d'accès actuel.
            },
        });

        await transporter.sendMail(mailOptions);  // Envoi de l'email avec les options définies.
        console.log("Activation email sent successfully to:", email);  // Affiche que l'email a été envoyé avec succès.

        // Affiche un message de succès à l'utilisateur et le redirige vers la page de connexion.
        req.flash('success_msg', 'Lien d’activation envoyé. Vérifiez votre boîte mail.');
        res.redirect('/auth/login');  // Redirige vers la page de connexion.
    } catch (error) {
        console.error("Error during registration process:", error);  // En cas d'erreur, on l'affiche dans la console.
        req.flash('error_msg', 'Une erreur est survenue. Veuillez réessayer.');  // Affiche un message d'erreur à l'utilisateur.
        res.redirect('/auth/register');  // Redirige l'utilisateur vers la page d'inscription en cas d'erreur.
    }
};
