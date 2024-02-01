const express = require('express');
const controller = require('../controllers/auth');
const router = express.Router();
const user = require('../models/User');

// localhost:5000/api/auth/login
router.post('/login', controller.login);

// localhost:5000/api/auth/register
router.post('/register', controller.register);

// GET-маршрут для подтверждения электронной почты
router.get('/verify-email/:token', controller.verifyEmail);

module.exports = router;