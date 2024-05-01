const express = require('express');
const bodyParser = require('body-parser');

// Initialize Express app
const app = express();
const PORT = process.env.PORT || 3000;

// Middleware to parse JSON bodies
app.use(bodyParser.json());

// Dummy data for tasks
let tasks = [
    { id: 1, title: 'Task 1', description: 'Description for Task 1' },
    { id: 2, title: 'Task 2', description: 'Description for Task 2' }
];

// GET all tasks
app.get('/tasks', (req, res) => {
    res.json(tasks);
});

// GET a single task by ID
app.get('/tasks/:id', (req, res) => {
    const taskId = parseInt(req.params.id);
    const task = tasks.find(task => task.id === taskId);
    if (!task) {
        return res.status(404).json({ message: 'Task not found' });
    }
    res.json(task);
});

// POST create a new task
app.post('/tasks', (req, res) => {
    const { title, description } = req.body;
    if (!title || !description) {
        return res.status(400).json({ message: 'Title and description are required' });
    }
    const newTask = {
        id: tasks.length + 1,
        title,
        description
    };
    tasks.push(newTask);
    res.status(201).json(newTask);
});

// PUT update an existing task by ID
app.put('/tasks/:id', (req, res) => {
    const taskId = parseInt(req.params.id);
    const taskIndex = tasks.findIndex(task => task.id === taskId);
    if (taskIndex === -1) {
        return res.status(404).json({ message: 'Task not found' });
    }
    const { title, description } = req.body;
    if (!title || !description) {
        return res.status(400).json({ message: 'Title and description are required' });
    }
    tasks[taskIndex] = {
        id: taskId,
        title,
        description
    };
    res.json(tasks[taskIndex]);
});

// DELETE a task by ID
app.delete('/tasks/:id', (req, res) => {
    const taskId = parseInt(req.params.id);
    const taskIndex = tasks.findIndex(task => task.id === taskId);
    if (taskIndex === -1) {
        return res.status(404).json({ message: 'Task not found' });
    }
    tasks.splice(taskIndex, 1);
    res.status(204).send();
});

// Start the server
app.listen(PORT, () => {
    console.log(Server is running on http://localhost:${PORT});
});
const Sequelize = require('sequelize');

// Initialize Sequelize with database connection parameters
const sequelize = new Sequelize('database_name', 'username', 'password', {
  host: 'localhost',
  dialect: 'mysql'
});

// Define the 'Task' model
const Task = sequelize.define('task', {
  title: {
    type: Sequelize.STRING,
    allowNull: false
  },
  description: {
    type: Sequelize.TEXT,
    allowNull: true
  }
});

// Synchronize the model with the database (create the 'tasks' table if it doesn't exist)
sequelize.sync()
  .then(() => {
    console.log('Database synchronized');
  })
  .catch(err => {
    console.error('Database synchronization failed:', err);
  });

// Export the Task model
module.exports = Task;
// Import required modules
const Task = require('./models/Task'); // Assuming you have defined the Task model using Sequelize or any other ORM

// Function to create a new task
async function createTask(title, description) {
    try {
        const newTask = await Task.create({
            title,
            description
        });
        return newTask;
    } catch (error) {
        throw new Error('Error creating task: ' + error.message);
    }
}
// Function to assign a task to a user
async function assignTask(taskId, userId) {
    try {
        const task = await Task.findByPk(taskId);
        if (!task) {
            throw new Error('Task not found');
        }
        // Assuming you have a 'userId' foreign key in the Task model
        task.userId = userId;
        await task.save();
        return task;
    } catch (error) {
        throw new Error('Error assigning task: ' + error.message);
    }
}
// Function to update the status of a task
async function updateTaskStatus(taskId, status) {
    try {
        const task = await Task.findByPk(taskId);
        if (!task) {
            throw new Error('Task not found');
        }
        task.status = status;
        await task.save();
        return task;
    } catch (error) {
        throw new Error('Error updating task status: ' + error.message);
    }
}
// Function to calculate task completion metrics
async function calculateTaskMetrics() {
    try {
        // Example: Counting tasks with different statuses
        const totalTasks = await Task.count();
        const completedTasks = await Task.count({ where: { status: 'completed' } });
        const pendingTasks = await Task.count({ where: { status: 'pending' } });
        const inProgressTasks = await Task.count({ where: { status: 'in_progress' } });

        return {
            totalTasks,
            completedTasks,
            pendingTasks,
            inProgressTasks
        };
    } catch (error) {
        throw new Error('Error calculating task metrics: ' + error.message);
    }
}
[10:43 pm, 1/5/2024] .: // Export the functions for use in other modules
module.exports = {
    createTask,
    assignTask,
    updateTaskStatus,
    calculateTaskMetrics
};
[10:43 pm, 1/5/2024] .: // Import required modules
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const JwtStrategy = require('passport-jwt').Strategy;
const { ExtractJwt } = require('passport-jwt');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

// Import your User model
const User = require('./models/User');
// Local strategy for username/password authentication
passport.use(new LocalStrategy({
    usernameField: 'email', // Assuming email is used for login
    passwordField: 'password'
}, async (email, password, done) => {
    try {
        // Find user by email
        const user = await User.findOne({ where: { email } });
        if (!user) {
            return done(null, false, { message: 'Incorrect email or password' });
        }
        // Validate password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return done(null, false, { message: 'Incorrect email or password' });
        }
        return done(null, user);
    } catch (error) {
        return done(error);
    }
}));
// JWT strategy for token-based authentication
passport.use(new JwtStrategy({
    jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
    secretOrKey: 'your_jwt_secret' // Change this to your own secret key
}, async (jwtPayload, done) => {
    try {
        // Find user by ID from JWT payload
        const user = await User.findByPk(jwtPayload.id);
        if (!user) {
            return done(null, false);
        }
        return done(null, user);
    } catch (error) {
        return done(error, false);
    }
}));

// Middleware to authenticate requests using JWT
const authenticateJWT = (req, res, next) => {
    passport.authenticate('jwt', { session: false }, (err, user, info) => {
        if (err) {
            return next(err);
        }
        if (!user) {
            return res.status(401).json({ message: 'Unauthorized' });
        }
        req.user = user;
        next();
    })(req, res, next);
};

// Authorization middleware to check user roles
const authorize = (roles) => {
    return (req, res, next) => {
        if (!roles.includes(req.user.role)) {
            return res.status(403).json({ message: 'Forbidden' });
        }
        next();
    };
};
// Function to generate JWT token
const generateToken = (user) => {
    const payload = {
        id: user.id,
        email: user.email,
        role: user.role
    };
    return jwt.sign(payload, 'your_jwt_secret', { expiresIn: '1h' }); // Change this to your own secret key and expiration time
};

module.exports = {
    authenticateJWT,
    authorize,
    generateToken
};
const express = require('express');
const router = express.Router();
const passport = require('passport');
const bcrypt = require('bcrypt');
const { authenticateJWT, authorize, generateToken } = require('./auth'); // Import your authentication middleware and functions
const User = require('./models/User');

// Route to authenticate user and generate JWT token
router.post('/login', (req, res, next) => {
    passport.authenticate('local', { session: false }, (err, user, info) => {
        if (err) {
            return next(err);
        }
        if (!user) {
            return res.status(401).json({ message: 'Invalid email or password' });
        }
        // Generate JWT token
        const token = generateToken(user);
        res.json({ token });
    })(req, res, next);
});

// Route to get current user profile (requires authentication)
router.get('/profile', authenticateJWT, (req, res) => {
    res.json(req.user);
});

// Route to create a new user
router.post('/register', async (req, res) => {
    try {
        const { email, password, role } = req.body;
        // Hash password before saving to database
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = await User.create({ email, password: hashedPassword, role });
        res.status(201).json(newUser);
    } catch (error) {
        res.status(400).json({ message: error.message });
    }
});

// Route to get all users (requires admin role)
router.get('/users', authenticateJWT, authorize(['admin']), async (req, res) => {
    try {
        const users = await User.findAll();
        res.json(users);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

module.exports = router;
