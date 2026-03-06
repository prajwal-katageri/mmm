# Photo Grabber

Capture photos from the browser camera, upload to a Node/Express server, and view them in a gallery.

## Run locally

1. Install dependencies:
   - `npm install`
2. Ensure MongoDB is running locally **or** set an Atlas connection string.
3. Configure env vars (optional but recommended):
   - Copy `.env.example` to `.env` and update values.
4. Start the server:
   - `npm start`
5. Open:
   - http://localhost:3500/

## Environment variables

- `PORT` (default: `3500`)
- `MONGODB_URI` (default: `mongodb://localhost:27017`)
- `DB_NAME` (default: `photo_grabber`)

## Deploy (high level)

You need:
- A Node.js hosting provider (Render/Railway/Fly.io/Azure App Service/etc.)
- A MongoDB database reachable from the internet (commonly MongoDB Atlas)

Set these environment variables in your hosting provider:
- `MONGODB_URI`
- `DB_NAME`
- `PORT` (many providers set this automatically)

Start command:
- `npm start`
