// Importation du module bcryptjs pour hacher les mots de passe de manière sécurisée
const bcryptjs = require('bcryptjs');

// Importation du modèle User pour interagir avec la base de données des utilisateurs
const User = require('../models/User');

/**
 * Vérifie si un mot de passe respecte les critères de sécurité
 * 
 * Critères :
 * - Au moins 8 caractères
 * - Au moins une lettre majuscule (A-Z)
 * - Au moins un chiffre (0-9)
 * - Au moins un caractère spécial (!, @, #, $, etc.)
 * 
 * @param {string} password - Le mot de passe à vérifier
 * @returns {boolean} - Retourne `true` si le mot de passe est valide, sinon `false`
 */
function isValidPassword(password) {
    // Définition d'une expression régulière (regex) pour valider les mots de passe
    const regex = /^(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,}$/; 
    return regex.test(password); // Teste si le mot de passe correspond aux critères
}

/**
 * Fonction permettant de réinitialiser le mot de passe d'un utilisateur
 * 
 * @param {Object} req - L'objet de requête HTTP contenant les données envoyées par le client
 * @param {Object} res - L'objet de réponse HTTP permettant de renvoyer une réponse au client
 */
exports.resetPassword = async (req, res) => {
    try {
        // Extraction des valeurs envoyées dans le corps de la requête (formulaire)
        const { password, password2 } = req.body;

        // Extraction de l'identifiant de l'utilisateur depuis l'URL
        const { id } = req.params;

        // Vérification que les champs ne sont pas vides
        if (!password || !password2) {
            req.flash('error_msg', 'Veuillez remplir tous les champs.'); // Message d'erreur
            return res.redirect(`/auth/reset/${id}`); // Redirection vers la page de réinitialisation
        }

        // Vérification que les deux mots de passe sont identiques
        if (password !== password2) {
            req.flash('error_msg', 'Les mots de passe ne correspondent pas.'); // Message d'erreur
            return res.redirect(`/auth/reset/${id}`); // Redirection vers la page de réinitialisation
        }

        // Vérification que le mot de passe respecte les critères de sécurité
        if (!isValidPassword(password)) {
            req.flash('error_msg', 'Le mot de passe doit contenir au moins 8 caractères, une majuscule, un chiffre et un caractère spécial.');
            return res.redirect(`/auth/reset/${id}`); // Redirection vers la page de réinitialisation
        }

        // Génération d'un "sel" (valeur aléatoire utilisée pour le hachage)
        const salt = await bcryptjs.genSalt(10);

        // Hachage du mot de passe avec le sel généré
        const hash = await bcryptjs.hash(password, salt);

        // Mise à jour du mot de passe haché dans la base de données pour l'utilisateur correspondant à l'ID
        const result = await User.findByIdAndUpdate(id, { password: hash });

        // Vérification si la mise à jour a réussi
        if (!result) {
            req.flash('error_msg', 'Erreur lors de la réinitialisation du mot de passe.');
            return res.redirect(`/auth/reset/${id}`); // Redirection en cas d'erreur
        }

        // Message de succès après mise à jour du mot de passe
        req.flash('success_msg', 'Mot de passe réinitialisé avec succès !');

        // Redirection vers la page de connexion pour que l'utilisateur puisse se reconnecter
        res.redirect('/auth/login');
        
    } catch (error) {
        // Capture et affichage de l'erreur dans la console pour le débogage
        console.error('Erreur lors de la réinitialisation du mot de passe :', error);

        // Message d'erreur général en cas de problème
        req.flash('error_msg', 'Une erreur est survenue. Veuillez réessayer.');

        // Redirection vers la page de connexion
        res.redirect('/auth/login');
    }
};
