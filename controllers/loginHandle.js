// Importation des modules nécessaires
const passport = require('passport');  // Pour l'authentification avec Passport
require('dotenv').config();  // Chargement des variables d'environnement

//------------ Login Handle ------------//
/**
 * Fonction pour gérer l'authentification d'un utilisateur via Passport.
 * Cette fonction vérifie les informations d'identification de l'utilisateur et redirige en fonction du résultat.
 * 
 * @param {Object} req - L'objet de la requête HTTP contenant les informations d'identification
 * @param {Object} res - L'objet de la réponse HTTP pour rediriger l'utilisateur
 * @param {Function} next - Fonction à appeler si l'authentification réussit ou échoue
 */
exports.loginHandle = (req, res, next) => {
    // Utilisation de la stratégie 'local' pour l'authentification
    passport.authenticate('local', {
        successRedirect: '/dashboard',  // Redirection vers le dashboard si l'authentification réussit
        failureRedirect: '/auth/login',  // Redirection vers la page de login en cas d'échec
        failureFlash: true  // Activation des messages flash d'erreur si l'authentification échoue
    })(req, res, next);  // Exécution de l'authentification avec les paramètres ci-dessus
};
