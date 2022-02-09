require("dotenv").config()

const mysql = require('mysql')
const express = require('express')
const app = express()
const cors = require('cors')
const jwt = require("jsonwebtoken")
const bcrypt = require("bcrypt")

app.use(express.json());
app.use(cors())
app.use(express.urlencoded({ extended: true}))

//Connect to db

const con = mysql.createConnection({
    host: "localhost",
    user: process.env.DB_USERNAME,
    password: process.env.DB_PASSWORD,
    database: "markdown"
})

con.connect(err => {
    if (err) throw err
    console.log('Connected!')

})

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers["authorization"]
    const token = authHeader && authHeader.split(" ")[1]
    console.log('/authenticate Authorizing in authtoken call, ', token)

    if(token == null) return res.sendStatus(401)

    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
        console.log('/authenticate verifying token')
        if (err) return res.sendStatus(403)
        req.username = user.user
        console.log('/authenticate user success: ', user)
        next()
    })
}

app.post('/login', (req, res) => {
    const username = req.body.username
    const password = req.body.password
    console.log('/login Username: ' + username + " password " + password)
    let userFromDB

    con.query(`SELECT * FROM USER WHERE username = '${username}'`, (err, result) => {
        if (err) return res.sendStatus(500)
        if (result[0] == undefined) return res.sendStatus(403)
        userFromDB = result[0]

        bcrypt.compare(password, userFromDB.password).then(result => {
            console.log('/login results, ', result)
            console.log('/login userfromdb, ', userFromDB)

            if(result == true) {
                const tokenExpireTime = '15m'
                const accessToken = jwt.sign({ user: userFromDB.username }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: tokenExpireTime})
                const refreshToken = jwt.sign({ user: userFromDB.username }, process.env.REFRESH_TOKEN_SECRET, { expiresIn: "4h"})
                // const refreshToken = jwt.sign(user, process.env.REFRESH_TOKEN_SECRET)
                // res.cookie('token', accessToken, {httpOnly: true})
                res.json({ accessToken: accessToken, refreshToken: refreshToken, expireTime: tokenExpireTime})
            } else {
                res.sendStatus(403)
            }
    
        }).catch(err => {
            console.log('/login error', err)
        })
    })
})

app.post('/refresh', (req, res) => {
    const token = req.body.token
    const tokenExpireTime = '15m'
    //not sure if user.username is valid here
    console.log('/refresh drefresh: ', token)
    jwt.verify(token, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
        if (err) return res.sendStatus(403)
        console.log('/refresh user: ', user)
        const accessToken = jwt.sign({user: user.user }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: tokenExpireTime})
        res.json({ accessToken: accessToken, expireTime: tokenExpireTime })
    })
})

app.post('/create-user', (req, res) => {
    const username = req.body.username
    const password = req.body.password

    bcrypt.hash(password, 10, (err, hash) => {
        if (err) return res.status(500).send(err)
        con.query(`INSERT INTO user VALUES ('${username}', '${hash}')`, (err, result) => {
            console.log('/create-user results from new user creation', result)
            const tokenExpireTime = '15m'
            const accessToken = jwt.sign({ user: username }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: tokenExpireTime})
            const refreshToken = jwt.sign({ user: username }, process.env.REFRESH_TOKEN_SECRET, { expiresIn: "4h"})
            // const refreshToken = jwt.sign(user, process.env.REFRESH_TOKEN_SECRET)
            // res.cookie('token', accessToken, {httpOnly: true})
            
            //create user settings in db
            con.query(`INSERT INTO settings VALUES ('###', '##', '#', '>', '\\*\\*', '\\*', '${username}')`, (err) => {
                console.log('error inserting into settings: ', err)
            })

            res.json({ accessToken: accessToken, refreshToken: refreshToken, expireTime: tokenExpireTime})
        })
    })
})

app.put('/update-password', authenticateToken, (req, res) => {
    console.log('/update-password user: ', req.username)
    console.log('/update-password password: ', req.body.password)
    const password = req.body.password

    bcrypt.hash(password, 10, (err, hash) => {
        con.query(`UPDATE user SET password = '${hash}' WHERE username = '${req.username}'`, (err, result) => {
            if (err) res.sendStatus(500)
            res.sendStatus(200)
        })
    })
})

app.listen(4000, () => {
    console.log('listening on port 4000')
})

