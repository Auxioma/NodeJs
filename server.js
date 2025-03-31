// Charge les variables d'environnement depuis un fichier .env
require('dotenv').config();

// Importe les modules nécessaires
const express = require('express'); // Framework pour créer un serveur web
const expressLayouts = require('express-ejs-layouts'); // Middleware pour gérer les layouts EJS
const mongoose = require('mongoose'); // Librairie pour interagir avec MongoDB
const flash = require('connect-flash'); // Middleware pour afficher des messages flash (ex: messages d'erreur)
const session = require('express-session'); // Middleware pour gérer les sessions utilisateur
const passport = require('passport'); // Middleware pour l'authentification
const helmet = require('helmet'); // Sécurise Express en configurant divers en-têtes HTTP
const rateLimit = require('express-rate-limit'); // Middleware pour limiter le nombre de requêtes
const MongoStore = require('connect-mongo'); // Permet de stocker les sessions dans MongoDB
const morgan = require('morgan'); // Middleware pour logger les requêtes HTTP
const path = require('path'); // Module pour travailler avec les chemins de fichiers

// Initialise une application Express
const app = express();

//------------ Configuration de Passport ------------//
require('./config/passport')(passport); // Charge la configuration de Passport

//------------ Configuration de la base de données ------------//
const db = process.env.MONGO_URI; // Récupère l'URL de connexion MongoDB depuis les variables d'environnement
if (!db) {
    console.error("Erreur : MONGO_URI n'est pas défini dans le fichier .env");
    process.exit(1); // Arrête l'exécution si la base de données n'est pas configurée
}

//------------ Connexion à MongoDB ------------//
mongoose.connect(db, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log("Successfully connected to MongoDB"))
    .catch(err => {
        console.error('Erreur de connexion à MongoDB :', err.message);
        process.exit(1);
    });

// Active Helmet pour sécuriser les en-têtes HTTP
app.use(helmet());
// Désactive l'en-tête "X-Powered-By" pour ne pas révéler la technologie utilisée
app.disable('x-powered-by');

//------------ Configuration de EJS ------------//
app.use(expressLayouts); // Active le middleware de layout EJS
app.use("/assets", express.static(path.join(__dirname, 'assets'))); // Définit un dossier statique pour les fichiers assets (CSS, JS, images)
app.set('view engine', 'ejs'); // Définit EJS comme moteur de template

//------------ Middleware pour analyser les données envoyées par les formulaires ------------//
app.use(express.urlencoded({ extended: false }));

//------------ Configuration des sessions Express ------------//
app.use(
    session({
        secret: process.env.SESSION_SECRET || 'default_secret', // Clé secrète pour signer les sessions
        resave: false, // Empêche la sauvegarde de la session si elle n'a pas été modifiée
        saveUninitialized: false, // N'enregistre pas les sessions vides
        store: MongoStore.create({ 
            mongoUrl: db, // Stocke les sessions dans MongoDB
            ttl: 24 * 60 * 60 // Durée de vie des sessions : 1 jour
        }),
        cookie: { secure: process.env.NODE_ENV === 'production' } // Utilise les cookies sécurisés en production (HTTPS requis)
    })
);

//------------ Initialisation de Passport ------------//
app.use(passport.initialize()); // Initialise Passport
app.use(passport.session()); // Active la gestion des sessions avec Passport

//------------ Middleware pour les messages flash ------------//
app.use(flash());

//------------ Variables globales accessibles dans les templates ------------//
app.use((req, res, next) => {
    res.locals.success_msg = req.flash('success_msg'); // Message de succès
    res.locals.error_msg = req.flash('error_msg'); // Message d'erreur personnalisé
    res.locals.error = req.flash('error'); // Message d'erreur Passport
    next(); // Passe à la suite des middlewares
});

//------------ Protection contre les attaques DDoS (limitation des requêtes) ------------//
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // Période de 15 minutes
    max: 100, // Limite chaque IP à 100 requêtes par période
    standardHeaders: true, // Retourne les infos de limitation dans les headers
    legacyHeaders: false // Désactive les headers obsolètes
});
app.use(limiter);

//------------ Définition des routes ------------//
app.use('/', require('./routes/index')); // Route principale
app.use('/auth', require('./routes/auth')); // Routes d'authentification

//------------ Logger en mode développement ------------//
if (process.env.NODE_ENV === 'development') {
    app.use(morgan('dev')); // Active le logging détaillé en mode développement
}

//------------ Démarrage du serveur ------------//
const PORT = process.env.PORT || 9093; // Définit le port du serveur
app.listen(PORT, () => console.log(`Server running on PORT ${PORT}`)); // Lance le serveur
