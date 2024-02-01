const mongoose = require("mongoose");
const Schema = mongoose.Schema

const userSchema = new mongoose.Schema({
    name: {
        type: String,
        minlength: 2,
        maxlength: 255,
        required: true
    },
    surname: {
        type: String,
        minlength: 2,
        maxlength: 255,
        required: true
    },
    middlename: {
        type: String,
        minlength: 2,
        maxlength: 255,
        required: true
    },
    email: {
        type: String,
        required: true,
        match: /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/
    },
    username: {
        ref: 'users',
        minlength: 2,
        maxlength: 15,
        type: String
    },
    password: {
        type: String,
        required: true,
        // match: /^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{3,}$/
    },
    is_confirmed: {
        type: Boolean,
        default: false,
    },
})

module.exports = mongoose.model('users', userSchema)