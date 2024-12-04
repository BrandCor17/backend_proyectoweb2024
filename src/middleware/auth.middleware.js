// authMiddleware.js
import jwt from 'jsonwebtoken';
import { config } from '../config/db.config.js';

const authMiddleware = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'Access denied. No token provided.' });
  }

  try {
    const decoded = jwt.verify(token, config.jwtSecret); 

    if (!decoded.id) {
      return res.status(400).json({ message: 'Invalid token. User ID missing.' });
    }

    req.user = { _id: decoded.id, role: decoded.role }; 

    next(); 
  } catch (error) {
    console.error("Error de validación de token:", error);
    res.status(401).json({ message: 'Invalid token.' });
  }
};

export default authMiddleware;
