// Importation des modules nécessaires
const passport = require('passport'); // Middleware pour l'authentification
const bcryptjs = require('bcryptjs'); // Librairie pour le hachage des mots de passe
const nodemailer = require('nodemailer'); // Module pour envoyer des emails
const { google } = require("googleapis"); // Utilisation des API Google
const jwt = require('jsonwebtoken'); // Gestion des tokens JWT
const User = require('../models/User'); // Modèle utilisateur

// Importation des variables de configuration
const {
    GOOGLE_CLIENT_ID,
    GOOGLE_CLIENT_SECRET,
    GOOGLE_CLIENT_TOKEN,
    JWT_KEY,
    JWT_RESET_KEY,
} = require('../config/config');

//------------ Fonction de validation du mot de passe ------------//
/**
 * Vérifie si un mot de passe est suffisamment sécurisé.
 * 
 * Critères :
 * - Au moins 8 caractères
 * - Au moins une lettre majuscule
 * - Au moins un chiffre
 * - Au moins un caractère spécial
 * 
 * @param {string} password - Le mot de passe à valider
 * @returns {boolean} - Retourne true si le mot de passe est valide, sinon false
 */
function isValidPassword(password) {
    const regex = /^(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,}$/; 
    return regex.test(password);
}

//------------ Contrôleur pour la réinitialisation du mot de passe ------------//
/**
 * Permet à un utilisateur d'accéder à la page de réinitialisation de mot de passe 
 * en vérifiant la validité du token reçu par email.
 * 
 * @param {object} req - L'objet de requête Express contenant le token dans req.params
 * @param {object} res - L'objet de réponse Express pour rediriger l'utilisateur
 */
exports.gotoReset = async (req, res) => {
    try {
        const { token } = req.params; // Récupération du token depuis les paramètres d'URL

        // Vérification si le token est bien fourni
        if (!token) {
            req.flash('error_msg', 'Lien invalide ou expiré.'); // Message d'erreur pour l'utilisateur
            return res.redirect('/auth/login'); // Redirection vers la page de connexion
        }

        // Décodage du token JWT avec la clé secrète pour vérifier son authenticité
        const decodedToken = jwt.verify(token, JWT_RESET_KEY);
        
        // Vérification si le token est valide et contient un identifiant utilisateur
        if (!decodedToken || !decodedToken._id) {
            req.flash('error_msg', 'Lien incorrect ou expiré.');
            return res.redirect('/auth/login');
        }

        // Recherche de l'utilisateur correspondant à l'ID extrait du token
        const user = await User.findById(decodedToken._id);
        
        // Vérification si l'utilisateur existe
        if (!user) {
            req.flash('error_msg', 'Lien incorrect ou expiré.');
            return res.redirect('/auth/login');
        }

        // Redirection vers la page de réinitialisation du mot de passe avec l'ID utilisateur
        return res.redirect(`/auth/reset/${user._id}`);

    } catch (error) {
        // En cas d'erreur (ex: token expiré, invalide ou problème serveur)
        console.error("Erreur de réinitialisation du mot de passe :", error);
        req.flash('error_msg', 'Une erreur est survenue. Veuillez réessayer.');
        return res.redirect('/auth/login'); // Redirection sécurisée vers la connexion
    }
};
