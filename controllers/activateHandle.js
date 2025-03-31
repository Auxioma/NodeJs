const bcryptjs = require('bcryptjs'); // Module pour le hachage des mots de passe
const jwt = require('jsonwebtoken'); // Module pour la gestion des tokens JWT
require('dotenv').config();  // Charge les variables d'environnement depuis un fichier .env

//------------ Importation du modèle User ------------//
const User = require('../models/User'); // Modèle d'utilisateur utilisé pour interagir avec la base de données

//------------ Chargement des variables d'environnement ------------//
const { 
    JWT_KEY, // Clé secrète pour signer et vérifier les tokens JWT
} = process.env;  

//------------ Fonction pour activer un compte utilisateur ------------//
exports.activateHandle = async (req, res) => {
    console.log("[INFO] Requête d'activation reçue.");
    const token = req.params.token;  // Récupère le token d'activation depuis l'URL

    if (!token) {  // Vérifie si le token est absent
        console.log("[ERROR] Token d'activation manquant.");
        req.flash('error_msg', 'Activation token missing!'); // Affiche un message d'erreur
        return res.redirect('/auth/register');  // Redirige vers la page d'inscription
    }

    try {
        console.log("[INFO] Vérification du token JWT...");
        // Vérifie et décode le token avec la clé secrète JWT
        const decodedToken = jwt.verify(token, JWT_KEY);
        console.log("[SUCCESS] Token valide. Extraction des informations utilisateur...");
        
        // Extraction des informations utilisateur contenues dans le token
        const { name, email, password } = decodedToken;  

        console.log(`[INFO] Vérification de l'existence de l'utilisateur avec l'email: ${email}`);
        // Vérifie si un utilisateur avec cet email existe déjà dans la base de données
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            console.log("[ERROR] Email déjà enregistré.");
            req.flash('error_msg', 'Cet email est déjà enregistré! Veuillez vous connecter.');
            return res.redirect('/auth/login');  // Redirige vers la connexion si l'email est déjà pris
        }

        console.log("[INFO] Création d'un nouvel utilisateur...");
        // Création d'un nouvel utilisateur avec les informations fournies
        const newUser = new User({ name, email, password });

        console.log("[INFO] Génération du sel pour le hachage du mot de passe...");
        // Hachage du mot de passe avant de l'enregistrer dans la base de données
        const salt = await bcryptjs.genSalt(10); // Génère un sel unique pour le hachage
        console.log("[SUCCESS] Sel généré.");

        console.log("[INFO] Hachage du mot de passe...");
        newUser.password = await bcryptjs.hash(password, salt); // Hache le mot de passe avec bcryptjs
        console.log("[SUCCESS] Mot de passe haché.");

        console.log("[INFO] Sauvegarde de l'utilisateur dans la base de données...");
        await newUser.save();  // Sauvegarde l'utilisateur dans la base de données
        console.log("[SUCCESS] Utilisateur enregistré avec succès.");

        // Message de succès pour informer l'utilisateur que son compte est activé
        req.flash('success_msg', 'Compte activé. Vous pouvez maintenant vous connecter.');
        console.log("[INFO] Redirection vers la page de connexion.");
        res.redirect('/auth/login');  // Redirige vers la page de connexion

    } catch (err) {
        // Gestion des erreurs (ex: token invalide ou expiré)
        console.error('[ERROR] Erreur lors de l\'activation du compte:', err); // Affiche l'erreur dans la console
        req.flash('error_msg', 'Le lien est incorrect ou a expiré. Veuillez vous inscrire à nouveau.');
        res.redirect('/auth/register');  // Redirige vers l'inscription en cas d'erreur
    }
};
