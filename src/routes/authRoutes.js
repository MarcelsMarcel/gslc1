import express from 'express'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
import db from '../db.js'

const router = express.Router()

// Register a new user endpoint
router.post('/register', (req, res) => {
    const { username, password } = req.body
    //save the username and encrypted password

    // encrypt the password
    const hashedPassword = bcrypt.hashSync(password, 8)
    
    // save the new user and hashed password to DB
    try {
        const insertUser = db.prepare(`INSERT INTO user (username, password)
            VALUES (?, ?)`)
            const result = insertUser.run(username, hashedPassword)

        // now that we have a new user, we add their first todo
        const defaultTodo = 'Hello! Add your first todo!'
        const insertTodo = db.prepare(`INSERT INTO todos (user_id, task)
            VALUES(?, ?)`)
        insertTodo.run(result.lastInsertRowid, defaultTodo)

        // Create a token
        const token = jwt.sign({id: result.lastInsertRowid}, process.env.JWT_SECRET, {expiresIn: '24h'})
        res.json({token})
    } catch (err) {
        console.log(err.message)
        res.sendStatus(503)
    }
})

router.post('/login', (req, res) => {
    // we get their email, and we look up the password associated
    // with the email, but its encrypted. So we just encrypt the password
    // the user had just entered 
    const {username, password} = req.body

    try {
        const getUser = db.prepare('SELECT * FROM user WHERE username = ?')
        const user = getUser.get(username)

        if (!user) {
            return res.status(404).send({message:"User not found"})
        }

        const passwordIsValid = bcrypt.compareSync(password, user.password)
        if (!passwordIsValid) {
            return res.status(401).send({message: "Invalid Password"})
        }
        console.log(user)
        //If we pass, then we have a successfull auth
        const token = jwt.sign({id: user.id}, process.env.JWT_SECRET, {expiresIn: '24h'})
        res.json({token})
    } catch (err) {
        console.log(err.message)
        res.sendStatus(503)
    }
})

export default router