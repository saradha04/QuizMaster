const jwt = require('jsonwebtoken');
const User = require('../models/User'); // Import your User model

module.exports = async function (req, res, next) {
    console.log("Auth middleware");
    const token = req.header('x-auth-token');

    console.log(token);
    if (!token) return res.status(401).json({ msg: 'No token, authorization denied' });

    try {
        // Verify the token
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded.user; // Add the user ID to the request object

        // Check if the user exists
        const user = await User.findById(req.user.id); // Assuming the user ID is stored in the token
        if (!user) return res.status(401).json({ msg: 'User  does not exist' });

        // Check if the user changed their password after the token was issued
        const tokenIssuedAt = decoded.iat * 1000; // Convert to milliseconds
        if (user.passwordChangedAt && user.passwordChangedAt > tokenIssuedAt) {
            return res.status(401).json({ msg: 'Password has been changed, please log in again' });
        }

        console.log('Authentication successful for user:', req.user);
        next();
    } catch (err) {
        console.error(err);
        res.status(401).json({ msg: 'Token is not valid' });
    }
};
