// server.js
import express from 'express';
import mysql from 'mysql2';
import bcrypt from 'bcrypt';
import bodyParser from 'body-parser';


const app = express();
const port = 3000;

// Use body-parser middleware to parse JSON requests
app.use(bodyParser.json());

// Create MySQL database connection
const connection = mysql.createConnection({
    host: 'localhost',
    user: 'your_mysql_username',
    password: 'your_mysql_password',
    database: 'your_database_name',
});

// Connect to the database
connection.connect((err) => {
    if (err) {
        console.error('Error connecting to MySQL database:', err);
    } else {
        console.log('Connected to MySQL database');
    }
});

// Endpoint for user sign-up
app.post('/signup', async (req, res) => {
    const { username, email, password } = req.body;

    try {
        // Hash the password using bcrypt
        const hashedPassword = await bcrypt.hash(password, 10);

        // Insert user into the database
        const insertQuery = 'INSERT INTO users (username, email, password) VALUES (?, ?, ?)';
        connection.query(insertQuery, [username, email, hashedPassword], (error, results) => {
            if (error) {
                // Check for duplicate entry error
                if (error.code === 'ER_DUP_ENTRY') {
                    return res.status(400).json({ error: 'Email is already registered.' });
                }
                console.error('Error during sign-up:', error);
                return res.status(500).json({ error: 'Internal Server Error' });
            }

            return res.status(201).json({ message: 'User registered successfully.' });
        });
    } catch (error) {
        console.error('Error during password hashing:', error);
        return res.status(500).json({ error: 'Internal Server Error' });
    }
});

// Endpoint for user login
app.post('/login', (req, res) => {
    const { email, password } = req.body;

    // Retrieve user from the database based on email
    const selectQuery = 'SELECT * FROM users WHERE email = ?';
    connection.query(selectQuery, [email], async (error, results) => {
        if (error) {
            console.error('Error during login:', error);
            return res.status(500).json({ error: 'Internal Server Error' });
        }

        if (results.length === 0) {
            return res.status(401).json({ error: 'Invalid credentials.' });
        }

        // Compare the hashed password
        const isPasswordValid = await bcrypt.compare(password, results[0].password);
        if (!isPasswordValid) {
            return res.status(401).json({ error: 'Invalid credentials.' });
        }

        return res.status(200).json({ message: 'Login successful.' });
    });
});

// Start the server
app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});
