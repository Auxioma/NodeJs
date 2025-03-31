const express = require('express');
const router = express.Router();
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const sanitize = require('express-mongo-sanitize');
const authController = require('../controllers/authController');
const register = require('../controllers/registerHandle');
const activationMail = require('../controllers/activateHandle');
const forgot =require('../controllers/forgotPassword');
const gotoReset = require('../controllers/gotoReset')

// Configuration de base de sécurité
router.use(helmet());
router.use(sanitize());
router.use(express.urlencoded({ extended: true, limit: '10kb' }));

// Limiteur de requêtes de login
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 10, // limite à 10 connexions / IP
    message: 'Trop de tentatives de connexion, veuillez réessayer plus tard',
});

// Liste des routes GET pour le module d'authentification
const getRoutes = [
    { path: '/login', view: 'login' },
    { path: '/forgot', view: 'forgot' },
    { path: '/register', view: 'register' },
];

// Liste des routes GET avec paramètres
const getParamRoutes = [
    { path: '/reset/:id', view: 'reset', param: 'id' },
    { path: '/activate/:token', handle: activationMail.activateHandle },
    { path: '/forgot/:token', handle: authController.gotoReset },
];

// Liste des routes POST avec paramètres
const postRoutes = [
    { path: '/register', handle: register.registerHandle },
    { path: '/forgot', handle: forgot.forgotPassword },
    { path: '/login', handle: authController.loginHandle },
    { path: '/reset/:id', handle: authController.resetPassword },
];

// Configuration des routes GET
getRoutes.forEach((route) => {
    router.get(route.path, (req, res) => {
        if (route.view) {
            res.render(route.view); // Rendre la vue si elle est définie
        } else {
            res.status(400).send('View not defined for route: ' + route.path); // Afficher un message d'erreur si la vue n'est pas définie
        }
    });
});

// Génération des routes GET avec paramètres
getParamRoutes.forEach((route) => {
    if (route.view) {
        // Si route.view est définie, on rend la vue en ajoutant les paramètres
        router.get(route.path, (req, res) => res.render(route.view, { [route.param]: req.params[route.param] }));
    } else if (route.handle) {
        // Si route.handle est définie, on appelle le handler approprié
        router.get(route.path, route.handle);
    } else {
        // Si aucune vue ni handler n'est définie, on renvoie une erreur
        router.get(route.path, (req, res) => res.status(400).send('Handler or View missing for route: ' + route.path));
    }
});

// Génération des routes POST
postRoutes.forEach((route) => {
    router.post(route.path, authLimiter, route.handle);
});

router.get('/logout', authController.logoutHandle);

module.exports = router;
