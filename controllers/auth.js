const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const User = require('../models/User')
const keys = require('../config/keys')
const errorHandler = require('../utils/errorHandler')

module.exports.login = async function (req, res) {
    const candidate = await User.findOne({email: req.body.email})

    if (candidate) {
        const passwordResult = bcrypt.compareSync(req.body.password, candidate.password)
        if (passwordResult) {
        const token = jwt.sign({
            email: candidate.email,
            userId: candidate._id
        }, keys.jwt, {expiresIn: 60 * 60})

            res. status(200).json({
                token: `Bearer ${token}`
            })
        } else {
            res.status(401).json({
                message: "Пароль не совпадает"
            })
        }
    } else {
        res.status(404).json({
            message: "Пользователь не найден"
        })
    }
}

module.exports.register = async function (req, res) {
    try {
        const candidate = await User.findOne({email: req.body.email, username: req.body.username});
        if (candidate) {
            return res.status(409).json({ message: 'Почта или логин уже есть в базе' });
        } else {
            const salt = bcrypt.genSaltSync(10);
            const password = req.body.password;
            const hashedPassword = bcrypt.hashSync(password, salt);
            const newUser = new User({
                name: req.body.name,
                surname: req.body.surname,
                middlename: req.body.middlename,
                email: req.body.email, // Предполагается, что email является обязательным полем в модели User
                username: req.body.username, // Предполагается, что username является обязательным полем в модели User
                password: hashedPassword,
                is_confirmed: req.body.is_confirmed,
            });
            const savedUser = await newUser.save();
            res.status(201).json(savedUser);
        }
    } catch (e) {
        errorHandler(res, e)
    }
}

