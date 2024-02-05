const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const User = require('../models/User');
const keys = require('../config/keys');
const errorHandler = require('../utils/errorHandler');
const crypto = require('crypto');
const uuidv4 = require('uuid').v4;


const token = (payload, expiresIn) => {
    return jwt.sign(payload, keys.jwt, { expiresIn });
};

const transporter = nodemailer.createTransport({
    host: keys.SMTP_HOST,
    port: keys.SMTP_PORT,
    secure: false,
    auth: {
        user: keys.SMTP_USER,
        pass: keys.SMTP_PASSWORD
    }
});

const sendConfirmationEmail = async (email, token) => {
    const mailOptions = {
        from: 'node.jsautharization@gmail.com',
        to: email,
        subject: 'Подтверждение почты',
        text: `Пожалуйста, подтвердите свой email перейдя по ссылке: http://localhost:5000/api/verify-email/${token}`
    };
    await transporter.sendMail(mailOptions);
};

const generateEmailConfirmationToken = () => {
    return crypto.randomBytes(20).toString('hex');
};

module.exports.login = async function (req, res) {
    const candidate = await User.findOne({ email: req.body.email });
    if (candidate) {
        const passwordResult = await bcrypt.compare(req.body.password, candidate.password);
        if (passwordResult) {
            const accessToken = token({ email: candidate.email, userId: candidate._id }, '10m');
            const refreshToken = token({ email: candidate.email, userId: candidate._id }, '11m');
            res.status(200).json({
                AccessToken: accessToken,
                RefreshToken: refreshToken
            });
        } else {
            res.status(401).json({ message: 'Пароль не совпадает' });
        }
    } else {
        res.status(404).json({ message: 'Пользователь не найден' });
    }
};


exports.changePassword = async (req, res) => {
    const { email, oldPassword, newPassword } = req.body;
    const user = await User.findOne({ email: req.body.email });
    if (!user) {
        return res.status(404).json({ message: "Пользователь не найден" });
    }

    const passwordResult = await bcrypt.compare(oldPassword, user?.password);
    if (!passwordResult) {
        return res.status(401).json({ message: "Старый пароль неверный!" });
    } else {
        const salt = bcrypt?.genSaltSync(10);
        const hashedPassword = bcrypt?.hashSync(newPassword, salt);
        await User.updateOne({ email: email }, { password: hashedPassword });

        // Генерация токена подтверждения по почте и отправка письма
        const emailConfirmationToken = generateEmailConfirmationToken();
        await User.updateOne({ email: email }, { emailConfirmationToken }); // Сохранение токена в базе данных
        await sendConfirmationEmail(user?.email, emailConfirmationToken); // Отправка электронной почты с токеном подтверждения

        return res?.status(200).json({ message: "Для завершения смены пароля проверьте почту для подтверждения." });
    }
};

exports.verifyEmail = async (req, res) => {
    const token = req.params.token;
    try {
        const user = await User.findOneAndUpdate(
            { emailConfirmationToken: token },
            { $set: { is_confirmed: true, emailConfirmationToken: null }}
        );
        if (!user) {
            return res.status(404).json({ message: 'Неверный токен' });
        }
        return res.status(200).json({ message: 'Email успешно подтвержден.' });
    } catch (error) {
        console.error(error);
        return res.status(500).json({ message: 'Произошла ошибка' });
    }
};

module.exports.changePassword = async (req, res) => {
    const { email, oldPassword, newPassword } = req.body;
    try {
        const user = await User.findOne({ email: email });
        if (!user) {
            return res.status(404).json({ message: "Пользователь не найден" });
        }

        const passwordResult = await bcrypt.compare(oldPassword, user.password);
        if (!passwordResult) {
            return res.status(401).json({ message: "Старый пароль неверный!" });
        } else {
            const salt = bcrypt.genSaltSync(10);
            const hashedPassword = bcrypt.hashSync(newPassword, salt);
            await User.updateOne({ email: email }, { password: hashedPassword });

            const emailConfirmationToken = generateEmailConfirmationToken();
            await User.updateOne({ email: email }, { emailConfirmationToken });

            const mailOptions = {
                from: 'node.jsautharization@gmail.com',
                to: email,
                subject: 'Подтверждение смены пароля',
                text: `Ваш пароль успешно сменён: http://localhost:5000/api/verify-email/${emailConfirmationToken}`
            };
            await transporter.sendMail(mailOptions);
            return res.status(200).json({ message: "Для завершения смены пароля проверьте почту для подтверждения." });
        }
    } catch (error) {
        console.error(error);
        return res.status(500).json({ message: 'Произошла ошибка' });
    }
};


module.exports.register = async function (req, res) {
    try {
        const candidate = await User.findOne({ email: req.body.email, username: req.body.username });
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
                email: req.body.email,
                username: req.body.username,
                password: hashedPassword,
                is_confirmed: false, // Устанавливаем флаг is_confirmed в false при регистрации
                emailConfirmationToken: generateEmailConfirmationToken() // Генерируем токен подтверждения
            });
            const savedUser = await newUser.save();
            await sendConfirmationEmail(req.body.email, savedUser.emailConfirmationToken); // Используем savedUser для доступа к сгенерированному токену
            res.status(201).json(savedUser);
        }
    } catch (e) {
        errorHandler(res, e);
    }

};