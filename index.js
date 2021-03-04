const express = require('express');
const path = require('path');
const cookieSession = require('cookie-session');
const bcrypt = require('bcryptjs');
const dbConnection = require('./database');
const { body, validationResult } = require('express-validator');
const bodyParser = require('body-parser');
const { request } = require('http');

const app = express();
app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));

// SET OUR VIEWS AND VIEW ENGINE
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

// APPLY COOKIE SESSION MIDDLEWARE
app.use(cookieSession({
    name: 'session',
    keys: ['key1', 'key2'],
    maxAge: 3600 * 1000 // 1hr
}));

// DECLARING CUSTOM MIDDLEWARE
const ifNotLoggedin = (req, res, next) => {
    if (!req.session.isLoggedIn) {
        return res.render('login');
    }
    next();
}


const ifLoggedin = (req, res, next) => {
        if (req.session.isLoggedIn) {
            return res.redirect('/home');
        }
        next();
    }
    // END OF CUSTOM MIDDLEWARE

// ROUTE REGISTER
app.get('/register', function(req, res, next) {
    res.render('register')
})

// ROUTE SUCCESS
app.get('/success', function(req, res, next) {
    res.render('success')
})

// ROUTE EDIT
app.get('/edit', function(req, res, next) {
    res.render('edit')
})

// EDIT PAGE
app.post('/save-edit', function(req, res) {
    var id = req.session.userID;

    const validation_result = validationResult(req);
    const { user_edit } = req.body;
    // IF validation_result HAS NO ERROR
    if (validation_result.isEmpty()) {
        // password encryption (using bcryptjs)
        bcrypt.hash(user_edit, 12).then((hash_pass) => {
                // INSERTING USER INTO DATABASE
                dbConnection.execute("UPDATE users SET name='" + user_edit + "' where id='" + [id] + "'")
                    .then(result => {
                        res.redirect('/');
                    }).catch(err => {
                        // THROW INSERTING USER ERROR'S
                        if (err) throw err;
                    });
            })
            .catch(err => {
                // THROW HASING ERROR'S
                if (err) throw err;
            })
    } else {
        // COLLECT ALL THE VALIDATION ERRORS
        let allErrors = validation_result.errors.map((error) => {
            return error.msg;
        });
        // REDERING login-register PAGE WITH VALIDATION ERRORS
        res.render('edit', {
            register_error: allErrors,
            old_data: req.body
        });
    }
});

// DELETE PAGE
app.get('/delete/:id', function(req, res, next) {
    var id = req.session.userID;
    var sql = 'DELETE FROM `users` WHERE id = ?';
    dbConnection.query(sql, [id], function(err, data) {
        if (err) throw err;
        console.log(data.affectedRows + " record(s) updated");
    });
    req.session = null;
    res.redirect('/');

});

// ROOT PAGE
app.get('/', ifNotLoggedin, (req, res, next) => {
    dbConnection.execute("SELECT `name` FROM `users` WHERE `id`=?", [req.session.userID])
        .then(([rows]) => {
            res.render('home', {
                name: rows[0].name
            });
        });

}); // END OF ROOT PAGE


// REGISTER PAGE
app.post('/register-sub', ifLoggedin,
    // post data validation(using express-validator)
    [
        body('user_email', 'Invalid email address!').isEmail().custom((value) => {
            return dbConnection.execute('SELECT `email` FROM `users` WHERE `email`=?', [value])
                .then(([rows]) => {
                    if (rows.length > 0) {
                        return Promise.reject('This E-mail already in use!');
                    }
                    return true;
                });
        }),
        body('user_name', 'Username is Empty!').trim().not().isEmpty(),
        body('user_pass', 'The password must be of minimum length 6 characters').trim().isLength({ min: 6 }),
    ], // end of post data validation
    (req, res, next) => {

        const validation_result = validationResult(req);
        const { user_name, user_pass, user_email } = req.body;
        // IF validation_result HAS NO ERROR
        if (validation_result.isEmpty()) {
            // password encryption (using bcryptjs)
            bcrypt.hash(user_pass, 12).then((hash_pass) => {
                    // INSERTING USER INTO DATABASE
                    dbConnection.execute("INSERT INTO `users`(`name`,`email`,`password`) VALUES(?,?,?)", [user_name, user_email, hash_pass])
                        .then(result => {
                            res.redirect('/success');
                        }).catch(err => {
                            // THROW INSERTING USER ERROR'S
                            if (err) throw err;
                        });
                })
                .catch(err => {
                    // THROW HASING ERROR'S
                    if (err) throw err;
                })
        } else {
            // COLLECT ALL THE VALIDATION ERRORS
            let allErrors = validation_result.errors.map((error) => {
                return error.msg;
            });
            // REDERING login-register PAGE WITH VALIDATION ERRORS
            res.render('register', {
                register_error: allErrors,
                old_data: req.body
            });
        }
    }); // END OF REGISTER PAGE

// LOGIN PAGE
app.post('/', ifLoggedin, [
    body('user_email').custom((value) => {
        return dbConnection.execute('SELECT `email` FROM `users` WHERE `email`=?', [value])
            .then(([rows]) => {
                if (rows.length == 1) {
                    return true;

                }
                return Promise.reject('Invalid Email Address!');

            });
    }),
    body('user_pass', 'Password is empty!').trim().not().isEmpty(),
], (req, res) => {
    const validation_result = validationResult(req);
    const { user_pass, user_email } = req.body;
    if (validation_result.isEmpty()) {

        dbConnection.execute("SELECT * FROM `users` WHERE `email`=?", [user_email])
            .then(([rows]) => {
                // console.log(rows[0].password);
                bcrypt.compare(user_pass, rows[0].password).then(compare_result => {
                        if (compare_result === true) {
                            req.session.isLoggedIn = true;
                            req.session.userID = rows[0].id;

                            res.redirect('/');
                        } else {
                            res.render('login', {
                                login_errors: ['Invalid Password!']
                            });
                        }
                    })
                    .catch(err => {
                        if (err) throw err;
                    });


            }).catch(err => {
                if (err) throw err;
            });
    } else {
        let allErrors = validation_result.errors.map((error) => {
            return error.msg;
        });
        // REDERING login-register PAGE WITH LOGIN VALIDATION ERRORS
        res.render('login', {
            login_errors: allErrors
        });
    }
});
// END OF LOGIN PAGE

// LOGOUT
app.get('/logout', (req, res) => {
    //session destroy
    req.session = null;
    res.redirect('/');
});
// END OF LOGOUT

app.use('/', (req, res) => {
    res.status(404).send('<h1>404 Page Not Found!</h1>');
});

app.listen(3000, () => console.log("Server is Running..."));