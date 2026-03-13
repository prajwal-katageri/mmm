/* global use, db */
// MongoDB Playground — Photo Grabber DB init
// Run this while connected to your Atlas cluster in the MongoDB VS Code extension.

// Use the same DB name as your app's DB_NAME
use('photo_grabber');

// Ensure collections exist (Mongo will also auto-create on first insert)
db.createCollection('users');
db.createCollection('photos');
db.createCollection('sessions');

// Match server expectations / common query patterns
// server.js creates this index on startup too; keeping it here makes the DB ready even before first run.
db.getCollection('users').createIndex({ username: 1 }, { unique: true });

// Helpful indexes for the app
// - photos are queried by userId and sorted by uploadedAt
// - sessions are looked up by token and filtered by expiresAt

// Note: userId is stored as an ObjectId in the app.
db.getCollection('photos').createIndex({ userId: 1, uploadedAt: -1 });

db.getCollection('sessions').createIndex({ token: 1 }, { unique: true });
// Optional cleanup: automatically remove expired sessions
// (safe with your app because it already treats expired sessions as invalid)
db.getCollection('sessions').createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 });

console.log('Photo Grabber DB initialized: photo_grabber');
