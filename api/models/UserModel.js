var mongoose = require('mongoose');
var bcrypt = require('bcrypt');
require("dotenv").config();
const jwt = require('jsonwebtoken');

const UserRole = require('../enums/UserRole');


var Schema = mongoose.Schema;

var UserSchema = new Schema({
    name: {
        type: String,
        required: [true, 'Name field is required!'],
        maxlength: 100
    },
    email: {
        type: String,
        required: [true, 'Email field is required!'],
        unique: true
    },
    username: {
        type: String,
        required: [true, 'Username field is required!'],
        unique: true
    },
    password: {
        type: String,
        minlength: 5,
        required: [true, 'Password field is required!']
    },
    role: {
        type: String,
        enum: UserRole,
        default: UserRole.CUSTOMER
    },
    profile_image: {
        type: String,
        required: false
    },
    phone_number: {
        type: String,
        required: false
    },
    created_date: {
        type: Date,
        default: Date.now
    }
});

// Saving user data
UserSchema.pre('save', function (next) {
    var user = this;
    if (user.isModified('password')) {
        //checking if password field is available and modified
        bcrypt.genSalt(SALT, function (err, salt) {
            if (err) return next(err)
        
            bcrypt.hash(user.password, salt, function (err, hash) {
                if (err) return next(err)
                user.password = hash;
                next();
            });
        });
    } else {
        next();
    }
});
     


const User = mongoose.model('User', UserSchema);
module.exports = { User }